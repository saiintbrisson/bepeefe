#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup/skb")
int entry(struct __sk_buff *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    const char fmt_str[] = "Pid: %d, buff len: %d\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), pid, ctx->len);

    return 1;
}
