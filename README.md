# simplebpf

学习用的 eBPF 小工具集 —— 计数器、丢包事件流、TCP flow 观测。

## 三个程序

| 程序 | 干啥 |
|---|---|
| **skb_count** | 数全局收到的 skb 数 |
| **drop_trace** | 内核协议栈丢包的实时事件流(带 reason + 函数位置) |
| **flow_dump** | mini-Hubble:TCP flow 观测,带去重和 TUI 刷新 |

## 前置

- Linux 内核 5.8+(推荐 6.x)
- BTF 开启(`/sys/kernel/btf/vmlinux` 存在)
- `clang-14`、`bpftool`、`go ≥ 1.20`

## 编译

```bash
make
```

## 运行

```bash
# skb_count
make skb_count-load
make skb_count-dump
make skb_count-unload

# drop_trace
make drop_trace-load
cd drop_reader && go run .
make drop_trace-unload

# flow_dump(Go 自加载 + TUI)
make flow_dump-run
```

## 测开销

```bash
make profile-all      # 自动起负载 + 测三个程序的 ns/call
```

## 不适合的场景

- 高速 gateway / 软路由(>1M PPS,主流量走 XDP,看不到)
- K8s 生产环境(装 Hubble 更合适)
