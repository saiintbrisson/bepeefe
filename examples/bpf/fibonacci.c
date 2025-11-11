/*
 * Fibonacci sequence with memoization.
 * 
 * This program is purely for demonstration. A real eBPF
 * program is not allowed to be recursive by the verifier.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, u64);
} fib_cache SEC(".maps");

long long fib_memo(int n) {
    if (n <= 1)
        return n;

    long long *cached = bpf_map_lookup_elem(&fib_cache, &n);
    if (cached)
        return *cached;

    int prev1 = n - 1;
    int prev2 = n - 2;
    long long val1 = fib_memo(prev1);
    long long val2 = fib_memo(prev2);
    long long result = val1 + val2;

    bpf_map_update_elem(&fib_cache, &n, &result, 0);
    return result;
}

long long entry(int n) {
    return fib_memo(n);
}
