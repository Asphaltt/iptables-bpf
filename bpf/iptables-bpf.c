#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

char _license[] SEC("license") = "GPL";


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, u32);
	__type(value, u8);
} filter_daddrs SEC(".maps");

SEC("socket")
int filter_iptables(void *skb) {
	struct iphdr iph;
	u8 *filtered;

	if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET) < 0)
		return BPF_OK;

	filtered = bpf_map_lookup_elem(&filter_daddrs, &iph.daddr);
	if (filtered != NULL && *filtered == 1)
		return BPF_DROP;

	return BPF_OK;
}