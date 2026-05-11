# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
BPFTOOL ?= bpftool
CLANG   ?= clang-14
VMLINUX := libbpf-bootstrap/vmlinux.h/include/x86/vmlinux.h

CFLAGS_BPF = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(dir $(VMLINUX))

.PHONY: all clean
all: skb_count.bpf.o drop_trace.bpf.o

%.bpf.o: %.bpf.c $(VMLINUX)
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

clean:
	rm -f *.bpf.o

# ---- skb_count: 包计数器 ----
SKB_PIN := /sys/fs/bpf/skb_count

.PHONY: skb_count-load skb_count-unload skb_count-dump
skb_count-load: skb_count.bpf.o
	mkdir -p $(SKB_PIN)
	$(BPFTOOL) prog loadall skb_count.bpf.o $(SKB_PIN) autoattach pinmaps $(SKB_PIN)
	@echo "map at $(SKB_PIN)/skb_count"

skb_count-unload:
	rm -rf $(SKB_PIN)

skb_count-dump:
	@$(BPFTOOL) map dump pinned $(SKB_PIN)/skb_count

# ---- drop_trace: kfree_skb 事件流 ----
DROP_PIN := /sys/fs/bpf/drop_trace

.PHONY: drop_trace-load drop_trace-unload
drop_trace-load: drop_trace.bpf.o
	mkdir -p $(DROP_PIN)
	$(BPFTOOL) prog loadall drop_trace.bpf.o $(DROP_PIN) autoattach pinmaps $(DROP_PIN)
	@echo "ringbuf at $(DROP_PIN)/events"

drop_trace-unload:
	rm -rf $(DROP_PIN)
