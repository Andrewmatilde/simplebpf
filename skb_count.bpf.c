// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} skb_count SEC(".maps");

SEC("tp/net/netif_receive_skb")
int count_skb(void *ctx)
{
	__u32 key = 0;
	__u64 *val = bpf_map_lookup_elem(&skb_count, &key);
	if (val)
		(*val)++;
	return 0;
}
