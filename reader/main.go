package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

func main() {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/skb_count/skb_count", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load pinned map:", err)
		os.Exit(1)
	}
	defer m.Close()

	var key uint32 = 0
	var perCPU []uint64
	if err := m.Lookup(&key, &perCPU); err != nil {
		fmt.Fprintln(os.Stderr, "lookup:", err)
		os.Exit(1)
	}

	var total uint64
	for i, v := range perCPU {
		fmt.Printf("  cpu%-3d %d\n", i, v)
		total += v
	}
	fmt.Printf("total skb: %d\n", total)
}
