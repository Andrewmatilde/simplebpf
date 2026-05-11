#!/usr/bin/env bash
# Profile BPF program runtime overhead by reading kernel-maintained
# run_cnt / run_time_ns over a sampling window.
#
# Usage: profile.sh [seconds]   default 5s

set -euo pipefail

DURATION=${1:-5}
BPFTOOL=${BPFTOOL:-bpftool}

# 我们关心的 BPF 入口函数(.bpf.c 里的 SEC 函数名)
PROGS=(count_skb on_kfree_skb on_xmit)

sysctl -w kernel.bpf_stats_enabled=1 > /dev/null

# 取所有同名 prog,把 run_cnt / run_time_ns 累加(避免残留 prog 失真)
snap_one() {
    local name=$1
    local out
    out=$($BPFTOOL prog show 2>/dev/null | grep " name $name" \
        | awk '{
            for (i=1; i<=NF; i++) {
                if ($i == "run_time_ns") t += $(i+1);
                if ($i == "run_cnt")     c += $(i+1);
            }
            n++;
        }
        END { if (n == 0) print "MISSING"; else printf "%d %d %d\n", c, t, n }')
    echo "$out"
}

declare -A T0
for p in "${PROGS[@]}"; do
    T0[$p]=$(snap_one "$p")
done

echo "sampling ${DURATION}s..."
sleep "$DURATION"

printf "\n%-18s %4s %12s %14s %12s %14s\n" \
    "PROGRAM" "inst" "calls" "ns total" "ns/call" "@1M PPS CPU"
printf -- "------------------ ---- ------------ -------------- ------------ --------------\n"

for p in "${PROGS[@]}"; do
    snap1=$(snap_one "$p")
    if [ "${T0[$p]}" = "MISSING" ] || [ "$snap1" = "MISSING" ]; then
        printf "%-18s %s\n" "$p" "(not loaded)"
        continue
    fi
    read -r c0 t0 n0 <<<"${T0[$p]}"
    read -r c1 t1 n  <<<"$snap1"
    dc=$((c1 - c0))
    dt=$((t1 - t0))
    if [ "$dc" -le 0 ]; then
        printf "%-18s %4d %12d %14d %12s %14s\n" "$p" "$n" "$dc" "$dt" "-" "-"
        continue
    fi
    avg=$(awk "BEGIN { printf \"%.1f\", $dt / $dc }")
    cpu=$(awk "BEGIN { printf \"%.2f%%\", ($dt / $dc) * 1000000 / 1e9 * 100 }")
    printf "%-18s %4d %12d %14d %12s %14s\n" "$p" "$n" "$dc" "$dt" "$avg" "$cpu"
done
