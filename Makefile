# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
BPFTOOL ?= bpftool
CLANG   ?= clang-14
VMLINUX := libbpf-bootstrap/vmlinux.h/include/x86/vmlinux.h

CFLAGS_BPF = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(dir $(VMLINUX))

.PHONY: all clean
all: skb_count.bpf.o drop_trace.bpf.o flow_dump/flow_dump

%.bpf.o: %.bpf.c $(VMLINUX)
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

clean:
	rm -f *.bpf.o
	rm -f flow_dump/flow_dump flow_dump/flowdump_*_bpfel.go flow_dump/flowdump_*_bpfel.o

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

# ---- flow_dump: tracepoint + ringbuf,Go 一把梭加载 ----
# bpf2go 把 BPF 编译进 Go skeleton,然后 go build 一个常驻二进制
.PHONY: flow_dump-build flow_dump-run flow_dump-generate

flow_dump-generate:
	cd flow_dump && PATH="$$(go env GOPATH)/bin:$$PATH" go generate

flow_dump/flow_dump: flow_dump.bpf.c flow_dump/main.go flow_dump/gen.go
	$(MAKE) flow_dump-generate
	cd flow_dump && go build -o flow_dump

flow_dump-build: flow_dump/flow_dump

flow_dump-run: flow_dump/flow_dump
	./flow_dump/flow_dump

# ---- 通用:测量三个程序的内核侧 BPF runtime 开销 ----
# 需要它们都在跑(make skb_count-load / drop_trace-load + 跑 flow_dump)
.PHONY: profile profile-on profile-off profile-all
profile:
	@scripts/profile.sh $${DURATION:-5}

# 一把梭:自动起 flow_dump + iperf3 loopback 持续打流 + 预热,然后采样
# 稳态高负载下的 ns/call 才是真实的生产开销,稀疏负载只代表冷启
profile-all: flow_dump/flow_dump
	@./flow_dump/flow_dump > /dev/null 2>&1 & FD=$$!; \
		iperf3 -s -1 -p 15201 > /dev/null 2>&1 & IPS=$$!; \
		sleep 0.3; \
		iperf3 -c 127.0.0.1 -p 15201 -t 30 > /dev/null 2>&1 & IPC=$$!; \
		echo "warming up 3s under iperf3 loopback load..."; \
		sleep 3; \
		scripts/profile.sh $${DURATION:-5}; \
		kill $$FD $$IPC $$IPS 2>/dev/null; wait 2>/dev/null; true

profile-on:
	@sysctl -w kernel.bpf_stats_enabled=1

profile-off:
	@sysctl -w kernel.bpf_stats_enabled=0
