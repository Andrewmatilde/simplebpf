// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
	__u64 ts_ns;
	__u64 skbaddr;
	__u64 location;
	__u32 reason;
	__u16 protocol;
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

SEC("tp/skb/kfree_skb")
int on_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
	__u32 reason = ctx->reason;

	/* 过滤"非真丢包"的常见噪声:
	 *   0  SKB_NOT_DROPPED_YET  内部值
	 *   1  SKB_CONSUMED         consume_skb 正常释放
	 *   2  NOT_SPECIFIED        reason 未补全的释放路径
	 *   5  SOCKET_FILTER        raw socket 自带的 cBPF filter 拒绝(预期行为)
	 */
	if (reason <= 2 || reason == 5)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns    = bpf_ktime_get_ns();
	e->skbaddr  = (__u64)(unsigned long)ctx->skbaddr;
	e->location = (__u64)(unsigned long)ctx->location;
	e->reason   = reason;
	e->protocol = ctx->protocol;
	e->pad      = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
