#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup/skb")
int entry(struct __sk_buff *ctx) {
    const char fmt_str[] = "Buff len: %d\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), ctx->len);

    return 1;
}
