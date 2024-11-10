static __attribute__((noinline)) __attribute__((section("sec1")))
int circle(int num) {
    return num * 10;
}

static __attribute__((noinline)) __attribute__((section("sec2")))
int square_the_circle(int num) {
    return circle(num) * circle(num);
}


int tringulate_the_squared_the_circle(int num) {
    return square_the_circle(num) * 3;
}

int entry() {
    int acc = 0;

    for (int i = 0; i < 10; i++) {
        acc += square_the_circle(3);
    }


    while (1) {
        acc -= tringulate_the_squared_the_circle(1);

        if (acc < 6300) {
            break;
        }
    }

    return acc;
}

