CLANG := clang
CLANG_INCLUDE := -I./bpf/headers

EBPF_SOURCE := ./bpf/iptables-bpf.c
EBPF_BINARY := iptables-bpf.elf
EBPF_PINNED := /sys/fs/bpf/iptbpf

GO := go
GOBUILD := $(GO) build -v

GO_SOURCE := main.go
GO_BINARY := iptables-bpf

.PHONY: build clean rebuild setup mapid

build: $(EBPF_BINARY) $(GO_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -g -target bpf -c $^  -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -o $(GO_BINARY) $(GO_SOURCE)

clean:
	rm -f $(EBPF_BINARY)
	rm -f $(GO_BINARY)
	iptables -D OUTPUT -m bpf --object-pinned $(EBPF_PINNED) -j DROP
	rm -f $(EBPF_PINNED)

rebuild: clean build

setup:
	bpftool prog load $(EBPF_BINARY) $(EBPF_PINNED)
	iptables -I OUTPUT -m bpf --object-pinned $(EBPF_PINNED) -j DROP

mapid:
	@bpftool map list | grep filter_daddrs | awk -F: '{print $$1}'
