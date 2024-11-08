#include <linux/bpf.h>

static __attribute__((noinline)) __attribute__((section("sec1")))
long circle(long num) {
    return num * 10;
}

static __attribute__((noinline)) __attribute__((section("sec2")))
long square_the_circle(long num) {
    return circle(num) * circle(num);
}


long tringulate_the_squared_the_circle(long num) {
    return square_the_circle(num) * 3;
}

// long global __attribute__((section("sec3")));

// void foo(long* num) {
//     *num += 1;
// }

long main() {
    long acc = 0;

    for (long i = 0; i < 10; i++) {
        acc += square_the_circle(3);
    }

    while (1) {
        acc -= tringulate_the_squared_the_circle(1);

        if (acc < 6300) {
            break;
        }
    }

    acc += 1;

    acc += (long) 783467328445424L;

    // acc += global;

    // foo(&acc);
    
    return acc;
}

