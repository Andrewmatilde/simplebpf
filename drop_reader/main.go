package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const ringbufPath = "/sys/fs/bpf/drop_trace/events"

type event struct {
	TsNs     uint64
	Skbaddr  uint64
	Location uint64
	Reason   uint32
	Protocol uint16
	_        uint16
}

func main() {
	rb, err := ebpf.LoadPinnedMap(ringbufPath, nil)
	if err != nil {
		fail("load pinned ringbuf: %v (did you `make drop_trace-load`?)", err)
	}
	defer rb.Close()

	r, err := ringbuf.NewReader(rb)
	if err != nil {
		fail("ringbuf reader: %v", err)
	}
	defer r.Close()

	syms, err := loadKallsyms()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: kallsyms unavailable (%v); locations shown as raw addr\n", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = r.Close()
	}()

	fmt.Printf("%-12s  %-6s  %-26s  %s\n", "TIME", "PROTO", "REASON", "LOCATION")

	bootNs := nowMonoNs() - timeSinceBootNs()

	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			fmt.Fprintln(os.Stderr, "read:", err)
			continue
		}

		var e event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			fmt.Fprintln(os.Stderr, "decode:", err)
			continue
		}

		ts := time.Unix(0, int64(bootNs+e.TsNs)).Format("15:04:05.000")
		proto := protoName(e.Protocol)
		reason := reasonName(e.Reason)
		loc := syms.resolve(e.Location)

		fmt.Printf("%-12s  %-6s  %-26s  %s\n", ts, proto, reason, loc)
	}
}

// ---------- kallsyms ----------

type kallsyms struct {
	addrs []uint64
	names []string
}

func loadKallsyms() (*kallsyms, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return &kallsyms{}, err
	}
	defer f.Close()

	var (
		addrs []uint64
		names []string
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 19 {
			continue
		}
		var addr uint64
		_, err := fmt.Sscanf(line[:16], "%x", &addr)
		if err != nil || addr == 0 {
			continue
		}
		fields := splitFields(line)
		if len(fields) < 3 {
			continue
		}
		addrs = append(addrs, addr)
		names = append(names, fields[2])
	}
	if len(addrs) == 0 {
		return &kallsyms{}, errors.New("kallsyms empty (need root or kptr_restrict=0)")
	}
	idx := make([]int, len(addrs))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(i, j int) bool { return addrs[idx[i]] < addrs[idx[j]] })
	sortedAddrs := make([]uint64, len(addrs))
	sortedNames := make([]string, len(names))
	for i, j := range idx {
		sortedAddrs[i] = addrs[j]
		sortedNames[i] = names[j]
	}
	return &kallsyms{addrs: sortedAddrs, names: sortedNames}, nil
}

func (k *kallsyms) resolve(addr uint64) string {
	if k == nil || len(k.addrs) == 0 {
		return fmt.Sprintf("0x%x", addr)
	}
	i := sort.Search(len(k.addrs), func(i int) bool { return k.addrs[i] > addr }) - 1
	if i < 0 {
		return fmt.Sprintf("0x%x", addr)
	}
	return fmt.Sprintf("%s+0x%x", k.names[i], addr-k.addrs[i])
}

func splitFields(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

// ---------- time ----------

func timeSinceBootNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

func nowMonoNs() uint64 {
	return uint64(time.Now().UnixNano())
}

// ---------- proto ----------

func protoName(p uint16) string {
	switch p {
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0x0806:
		return "ARP"
	case 0x8035:
		return "RARP"
	case 0x8100:
		return "VLAN"
	default:
		return fmt.Sprintf("0x%04x", p)
	}
}

// ---------- reason names ----------
// 来源:`/sys/kernel/tracing/events/skb/kfree_skb/format` 的 print fmt symbolic 表
// (内核 enum skb_drop_reason,值是 ABI,只增不减)

var reasonNames = map[uint32]string{
	2: "NOT_SPECIFIED", 3: "NO_SOCKET", 4: "SOCKET_CLOSE", 5: "SOCKET_FILTER",
	6: "SOCKET_RCVBUFF", 7: "UNIX_DISCONNECT", 8: "UNIX_SKIP_OOB", 9: "PKT_TOO_SMALL",
	10: "TCP_CSUM", 11: "UDP_CSUM", 12: "NETFILTER_DROP", 13: "OTHERHOST",
	14: "IP_CSUM", 15: "IP_INHDR", 16: "IP_RPFILTER", 17: "UNICAST_IN_L2_MULTICAST",
	18: "XFRM_POLICY", 19: "IP_NOPROTO", 20: "PROTO_MEM", 21: "TCP_AUTH_HDR",
	22: "TCP_MD5NOTFOUND", 23: "TCP_MD5UNEXPECTED", 24: "TCP_MD5FAILURE",
	25: "TCP_AONOTFOUND", 26: "TCP_AOUNEXPECTED", 27: "TCP_AOKEYNOTFOUND", 28: "TCP_AOFAILURE",
	29: "SOCKET_BACKLOG", 30: "TCP_FLAGS", 31: "TCP_ABORT_ON_DATA", 32: "TCP_ZEROWINDOW",
	33: "TCP_OLD_DATA", 34: "TCP_OVERWINDOW", 35: "TCP_OFOMERGE", 36: "TCP_RFC7323_PAWS",
	37: "TCP_RFC7323_PAWS_ACK", 38: "TCP_OLD_SEQUENCE", 39: "TCP_INVALID_SEQUENCE",
	40: "TCP_INVALID_ACK_SEQUENCE", 41: "TCP_RESET", 42: "TCP_INVALID_SYN",
	43: "TCP_CLOSE", 44: "TCP_FASTOPEN", 45: "TCP_OLD_ACK", 46: "TCP_TOO_OLD_ACK",
	47: "TCP_ACK_UNSENT_DATA", 48: "TCP_OFO_QUEUE_PRUNE", 49: "TCP_OFO_DROP",
	50: "IP_OUTNOROUTES", 51: "BPF_CGROUP_EGRESS", 52: "IPV6DISABLED",
	53: "NEIGH_CREATEFAIL", 54: "NEIGH_FAILED", 55: "NEIGH_QUEUEFULL", 56: "NEIGH_DEAD",
	57: "TC_EGRESS", 58: "SECURITY_HOOK", 59: "QDISC_DROP", 60: "QDISC_OVERLIMIT",
	61: "QDISC_CONGESTED", 62: "CAKE_FLOOD", 63: "FQ_BAND_LIMIT", 64: "FQ_HORIZON_LIMIT",
	65: "FQ_FLOW_LIMIT", 66: "CPU_BACKLOG", 67: "XDP", 68: "TC_INGRESS",
	69: "UNHANDLED_PROTO", 70: "SKB_CSUM", 71: "SKB_GSO_SEG", 72: "SKB_UCOPY_FAULT",
	73: "DEV_HDR", 74: "DEV_READY", 75: "FULL_RING", 76: "NOMEM",
	77: "HDR_TRUNC", 78: "TAP_FILTER", 79: "TAP_TXFILTER", 80: "ICMP_CSUM",
	81: "INVALID_PROTO", 82: "IP_INADDRERRORS", 83: "IP_INNOROUTES",
	84: "IP_LOCAL_SOURCE", 85: "IP_INVALID_SOURCE", 86: "IP_LOCALNET",
	87: "IP_INVALID_DEST", 88: "PKT_TOO_BIG", 89: "DUP_FRAG",
	90: "FRAG_REASM_TIMEOUT", 91: "FRAG_TOO_FAR", 92: "TCP_MINTTL",
	93: "IPV6_BAD_EXTHDR", 94: "IPV6_NDISC_FRAG", 95: "IPV6_NDISC_HOP_LIMIT",
	96: "IPV6_NDISC_BAD_CODE", 97: "IPV6_NDISC_BAD_OPTIONS",
	98: "IPV6_NDISC_NS_OTHERHOST", 99: "QUEUE_PURGE", 100: "TC_COOKIE_ERROR",
	101: "PACKET_SOCK_ERROR", 102: "TC_CHAIN_NOTFOUND", 103: "TC_RECLASSIFY_LOOP",
	104: "VXLAN_INVALID_HDR", 105: "VXLAN_VNI_NOT_FOUND", 106: "MAC_INVALID_SOURCE",
	107: "VXLAN_ENTRY_EXISTS", 108: "NO_TX_TARGET", 109: "IP_TUNNEL_ECN",
	110: "TUNNEL_TXINFO", 111: "LOCAL_MAC", 112: "ARP_PVLAN_DISABLE",
	113: "MAC_IEEE_MAC_CONTROL", 114: "BRIDGE_INGRESS_STP_STATE",
}

func reasonName(r uint32) string {
	if name, ok := reasonNames[r]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", r)
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
