#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Port -> Socket ID map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 128);
} open_ports SEC(".maps");

/* Socket ID-> Sock */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 128);
} sockets SEC(".maps");

SEC("sk_lookup/dispatch") int dispatch(struct bpf_sk_lookup *ctx) {
    __u32 port = ctx->local_port;
    __u32 *socket_id = bpf_map_lookup_elem(&open_ports, &port);
    if (!socket_id) return SK_PASS;

    void *sk = bpf_map_lookup_elem(&sockets, socket_id);
    if (!sk) {
        bpf_printk("port assigned to invalid socket (%d -> %d)", port, socket_id);
        return SK_DROP;
    }

    long err = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);

    return err ? SK_DROP : SK_PASS;
}

