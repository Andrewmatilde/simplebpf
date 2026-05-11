package main

//go:generate bpf2go -cc clang-14 -target amd64 -cflags "-O2 -g -Wall -I../libbpf-bootstrap/vmlinux.h/include/x86" flowDump ../flow_dump.bpf.c
