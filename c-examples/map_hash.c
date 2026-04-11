#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct stream_info {
    __u64 total;
    __u64 last;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct stream_info);
    __uint(max_entries, 65535);
} map SEC(".maps");

struct stream_packet_descriptor {
    __u32 stream_id;
    __u32 len;
};

SEC("cgroup/skb")
int entry(struct stream_packet_descriptor *ctx) {
    __u32 id = ctx->stream_id;
    __u32 total = ctx->len;
    __u32 last = 0;
    struct stream_info *acc = bpf_map_lookup_elem(&map, &id);

    if (acc) {
        total = __sync_add_and_fetch(&acc->total, ctx->len);
        last = __sync_val_compare_and_swap(&acc->last, acc->last, ctx->len);
    } else {
        struct stream_info i = {ctx->len, ctx->len};
        bpf_map_update_elem(&map, &id, &i, 0);
    }

    const char fmt_str[] = "streamId=%d, total=%d, last=%d\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), id, total, last);

    return total;
}
