package main

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	tableCapacity = 4096
	displayRows   = 40
	refreshEvery  = 500 * time.Millisecond
)

type flowKey struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

type flowEvent struct {
	TsNs    uint64
	Key     flowKey
	Ifindex uint32
	Len     uint32
}

type flowStat struct {
	key        flowKey
	iface      string
	firstSeen  time.Time
	lastSeen   time.Time
	eventCount uint64
	bytesTotal uint64
}

// LRU-ordered aggregate: 最新的在 list head,evict 从 tail
type aggregator struct {
	mu    sync.Mutex
	cap   int
	order *list.List
	index map[flowKey]*list.Element
}

func newAggregator(cap int) *aggregator {
	return &aggregator{
		cap:   cap,
		order: list.New(),
		index: make(map[flowKey]*list.Element, cap),
	}
}

func (a *aggregator) Touch(key flowKey, iface string, ts time.Time, bytes uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if elem, ok := a.index[key]; ok {
		s := elem.Value.(*flowStat)
		s.eventCount++
		s.bytesTotal += bytes
		s.lastSeen = ts
		s.iface = iface
		a.order.MoveToFront(elem)
		return
	}

	if len(a.index) >= a.cap {
		tail := a.order.Back()
		if tail != nil {
			a.order.Remove(tail)
			delete(a.index, tail.Value.(*flowStat).key)
		}
	}

	s := &flowStat{
		key:        key,
		iface:      iface,
		firstSeen:  ts,
		lastSeen:   ts,
		eventCount: 1,
		bytesTotal: bytes,
	}
	a.index[key] = a.order.PushFront(s)
}

func (a *aggregator) Snapshot() []flowStat {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]flowStat, 0, len(a.index))
	for e := a.order.Front(); e != nil; e = e.Next() {
		out = append(out, *e.Value.(*flowStat))
	}
	return out
}

func (a *aggregator) Size() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.index)
}

// ---------- main ----------

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fatal("rlimit: %v", err)
	}

	objs := flowDumpObjects{}
	if err := loadFlowDumpObjects(&objs, nil); err != nil {
		fatal("load BPF: %v", err)
	}
	defer objs.Close()

	tp, err := link.AttachTracing(link.TracingOptions{Program: objs.OnXmit})
	if err != nil {
		fatal("attach fentry: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fatal("ringbuf: %v", err)
	}
	defer rd.Close()

	agg := newAggregator(tableCapacity)
	bootNs := uint64(time.Now().UnixNano()) - timeSinceBootNs()
	ifaceCache := make(map[uint32]string)

	// ringbuf reader goroutine
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			var e flowEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
				continue
			}
			ts := time.Unix(0, int64(bootNs+e.TsNs))
			agg.Touch(e.Key, ifaceName(e.Ifindex, ifaceCache), ts, uint64(e.Len))
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// 进入 alternate screen,退出时还原
	fmt.Print("\x1b[?1049h\x1b[?25l") // alternate screen + hide cursor
	defer fmt.Print("\x1b[?25h\x1b[?1049l")

	ticker := time.NewTicker(refreshEvery)
	defer ticker.Stop()

	render(agg) // initial paint

	for {
		select {
		case <-ticker.C:
			render(agg)
		case <-sig:
			_ = rd.Close()
			return
		}
	}
}

// ---------- render ----------

func render(agg *aggregator) {
	snap := agg.Snapshot()
	sort.SliceStable(snap, func(i, j int) bool {
		return snap[i].lastSeen.After(snap[j].lastSeen)
	})

	var buf bytes.Buffer
	buf.WriteString("\x1b[H\x1b[2J") // home + clear

	now := time.Now()
	fmt.Fprintf(&buf, "flow_dump  active=%d/%d  %s\n",
		len(snap), tableCapacity, now.Format("15:04:05"))
	fmt.Fprintf(&buf, "%-12s %-9s %-22s %-22s %8s %10s %7s\n",
		"LAST", "IFACE", "SRC", "DST", "EVENTS", "BYTES", "AGE")

	n := displayRows
	if len(snap) < n {
		n = len(snap)
	}
	for i := 0; i < n; i++ {
		s := snap[i]
		age := now.Sub(s.firstSeen).Truncate(time.Second)
		fmt.Fprintf(&buf, "%-12s %-9s %-22s %-22s %8d %10s %7s\n",
			s.lastSeen.Format("15:04:05.000"),
			truncate(s.iface, 9),
			truncate(fmt.Sprintf("%s:%d", ipv4(s.key.Saddr), s.key.Sport), 22),
			truncate(fmt.Sprintf("%s:%d", ipv4(s.key.Daddr), s.key.Dport), 22),
			s.eventCount,
			humanBytes(s.bytesTotal),
			age,
		)
	}
	_, _ = os.Stdout.Write(buf.Bytes())
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func humanBytes(b uint64) string {
	const k = 1024
	switch {
	case b < k:
		return fmt.Sprintf("%dB", b)
	case b < k*k:
		return fmt.Sprintf("%.1fK", float64(b)/k)
	case b < k*k*k:
		return fmt.Sprintf("%.1fM", float64(b)/k/k)
	default:
		return fmt.Sprintf("%.1fG", float64(b)/k/k/k)
	}
}

func ipv4(addr uint32) string {
	return net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24)).String()
}

func ifaceName(idx uint32, cache map[uint32]string) string {
	if name, ok := cache[idx]; ok {
		return name
	}
	if iface, err := net.InterfaceByIndex(int(idx)); err == nil {
		cache[idx] = iface.Name
		return iface.Name
	}
	cache[idx] = fmt.Sprintf("if%d", idx)
	return cache[idx]
}

func timeSinceBootNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
