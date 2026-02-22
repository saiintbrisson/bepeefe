static __attribute__((noinline, used, section("sec1")))
long long is_prime(long long x) {
    if (x < 2) return 0;
    if (x == 2) return 1;
    if ((x & 1) == 0) return 0;
    for (long long i = 3; i * i <= x; i += 2)
        if (x % i == 0)
            return 0;
    return 1;
}

static __attribute__((noinline, used, section("sec2")))
long long sum_primes(int limit) {
    long long acc = 0;
    for (long long i = 2; i <= limit; ++i)
        if (is_prime(i))
            acc += i;
    return acc;
}

long long entry(int n) {
    long long total = sum_primes(n);
    long long modifier = n & 0xF;
    return total + modifier;
}

