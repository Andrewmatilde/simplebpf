// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6

struct flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

struct flow_event {
	__u64           ts_ns;
	struct flow_key key;
	__u32           ifindex;
	__u32           len;
};

#define REPORT_INTERVAL_NS (5ULL * 1000000000ULL)

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, __u64);
	__uint(max_entries, 65536);
} last_seen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("fentry/__dev_queue_xmit")
int BPF_PROG(on_xmit, struct sk_buff *skb)
{
	if (!skb)
		return 0;

	/* fentry 上下文里 skb 是 PTR_TO_BTF_ID,verifier 允许直接 deref */
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return 0;

	unsigned char *head = skb->head;
	__u16 nh = skb->network_header;
	__u16 th = skb->transport_header;

	/* head + nh 是 data buffer 区域,没有 BTF 信息,必须 probe_read */
	struct iphdr iph;
	if (bpf_probe_read_kernel(&iph, sizeof(iph), head + nh) < 0)
		return 0;
	if (iph.protocol != IPPROTO_TCP)
		return 0;

	__be16 ports[2];
	if (bpf_probe_read_kernel(ports, sizeof(ports), head + th) < 0)
		return 0;

	struct flow_key key = {
		.saddr = iph.saddr,
		.daddr = iph.daddr,
		.sport = bpf_ntohs(ports[0]),
		.dport = bpf_ntohs(ports[1]),
	};

	__u64 now = bpf_ktime_get_ns();
	__u64 *last = bpf_map_lookup_elem(&last_seen, &key);
	if (last && now - *last < REPORT_INTERVAL_NS)
		return 0;

	bpf_map_update_elem(&last_seen, &key, &now, BPF_ANY);

	struct flow_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns   = now;
	e->key     = key;
	/* 只在上报时读 ifindex,绝大多数包(去重命中)走不到这里 */
	e->ifindex = skb->dev ? skb->dev->ifindex : 0;
	e->len     = skb->len;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
