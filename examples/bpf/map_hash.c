#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __u32 ip;
    __u32 port;
} key;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, key);
    __type(value, long);
    __uint(max_entries, 65535);
} conn_map SEC(".maps");

SEC("cgroup/skb")
int entry(struct __sk_buff *ctx) {
    __u32 port = ctx->local_port;

    long *kbs = bpf_map_lookup_elem(&conn_map, &port);

    if (kbs) {
        __u64 acc = __sync_fetch_and_add(kbs, ctx->len);
        if ((acc % 4096) > 3072) {
            const char fmt_str[] = "Local port: %d, current buff len: %d\n";
            bpf_trace_printk(fmt_str, sizeof(fmt_str), port, acc);
        }
    }

    return 1;
}
