#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} fib_cache SEC(".maps");


int fib_memo(int n)
{
    if (n <= 1)
        return n;

    int *cached = bpf_map_lookup_elem(&fib_cache, &n);
    if (cached)
        return *cached;

    int prev1 = n - 1;
    int prev2 = n - 2;
    int val1 = fib_memo(prev1);  // safe because it's tail-controlled
    int val2 = fib_memo(prev2);
    int result = val1 + val2;

    bpf_map_update_elem(&fib_cache, &n, &result, 0);
    return result;
}

int entry(int n)
{
    return fib_memo(n);
}
