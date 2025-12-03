/*
 * Fibonacci sequence with memoization.
 * 
 * This program is purely for demonstration. A real eBPF
 * program is not allowed to be recursive by the verifier.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, long long);
} fib_cache SEC(".maps");

long long fibonacci(int n) {
    if (n <= 1)
        return n;

    long long *cached = bpf_map_lookup_elem(&fib_cache, &n);
    if (cached > 0 && *cached)
        return *cached;

    long long result = fibonacci(n - 1) + fibonacci(n - 2);

    if (cached > 0)
        __sync_val_compare_and_swap(cached, 0, result);

    return result;
}
