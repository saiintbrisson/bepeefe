#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_LEN 64
#define GRID_W 64
#define GRID_H 16
#define GRID_BYTES (GRID_W * GRID_H / 8)
#define DIE return -1
#define get_x(pos) ((pos) & 0xFF)
#define get_y(pos) ((pos) >> 8)
#define to_pos(x, y) (((x) & 0xFF) | ((y) << 8))

enum direction {
    up, right, down, left
};
enum color {
    color_clear, color_snake, color_food
};

struct snake {
    enum direction dir;
    __u8 len;
    __u8 head;
    __u16 body[MAX_LEN];
};

struct game {
    struct snake snake;
    __u8 food_x;
    __u8 food_y;
    __u8 grid[GRID_BYTES];
};

struct event {
    __u8 x;
    __u8 y;
    enum color color;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct game);
    __uint(max_entries, 1);
} state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __type(value, struct event);
    __uint(max_entries, GRID_W * GRID_H);
} render_events SEC(".maps");

static int update_position(struct game *state, __u32 rand) {
    __u64 head = (__u64)state->snake.head;
    if (head >= MAX_LEN) DIE;

    __u16 cur = state->snake.body[head];
    __s16 nx = get_x(cur);
    __s16 ny = get_y(cur);

    switch (state->snake.dir) {
      case up:    ny++; break;
      case right: nx++; break;
      case down:  ny--; break;
      case left:  nx--; break;
      default:    DIE;
    };

    if (nx < 0 || ny < 0 || nx >= GRID_W || ny >= GRID_H)
        DIE;

    __u64 len = (__u64)state->snake.len;
    if (len < 1 || len >= MAX_LEN) DIE;

    // grid cell for the new head position
    __u64 cell = (__u64)ny * GRID_W + (__u64)nx;
    __u64 byte_idx = cell >> 3;
    __u8 bit = 1 << (cell & 7);

    asm volatile("" : "+r"(byte_idx));
    if (byte_idx >= GRID_BYTES) DIE;

    __u8 ev_x, ev_y;
    enum color ev_color;

    if (nx == state->food_x && ny == state->food_y) {
        if (state->grid[byte_idx] & bit) DIE;
        state->snake.len = ++len;
        state->food_x = rand % GRID_W;
        state->food_y = rand / GRID_W;
        ev_x = state->food_x; ev_y = state->food_y; ev_color = color_food;
    } else {
        // remove tail from grid
        __u64 tail_idx = head + MAX_LEN + 1 - len;
        if (tail_idx >= MAX_LEN) tail_idx -= MAX_LEN;
        if (tail_idx >= MAX_LEN) DIE;

        __u16 tail = state->snake.body[tail_idx];
        __u64 tc = (__u64)get_y(tail) * GRID_W + (__u64)get_x(tail);
        __u64 tb = tc >> 3;
        if (tb >= GRID_BYTES) DIE;
        state->grid[tb] &= ~(1 << (tc & 7));

        // collision check after tail removal, snake can chase its tail
        if (state->grid[byte_idx] & bit) DIE;

        ev_x = get_x(tail); ev_y = get_y(tail); ev_color = color_clear;
    }

    // advance ring buffer and set grid bit
    state->grid[byte_idx] |= bit;
    __u64 new_head = head + 1;
    if (new_head >= MAX_LEN) new_head = 0;
    if (new_head >= MAX_LEN) DIE;
    state->snake.body[new_head] = to_pos(nx, ny);
    state->snake.head = (__u8) new_head;

    struct event event = {.x = ev_x, .y = ev_y, .color = ev_color};
    bpf_map_push_elem(&render_events, &event, 0);
    event = (struct event){.x = nx, .y = ny, .color = color_snake};
    bpf_map_push_elem(&render_events, &event, 0);

    return state->snake.len - 1;
}

struct tick_ctx {
    enum direction dir;
    __u32 rand;
};

SEC("game")
int on_tick(struct tick_ctx *ctx) {
    enum direction dir = ctx->dir;
    __u32 rand = ctx->rand;

    int idx = 0;
    int cell = rand % (GRID_W * GRID_H);
    struct game *state = bpf_map_lookup_elem(&state_map, &idx);

    if (state->snake.len == 0) {
        state->snake.dir = right;
        state->snake.len = 1;
        state->snake.head = 0;
        state->snake.body[0] = to_pos(0, GRID_H / 2);

        __u64 c = (__u64)(GRID_H / 2) * GRID_W;
        __u64 b = c >> 3;
        if (b < GRID_BYTES)
            state->grid[b] |= (1 << (c & 7));

        state->food_x = cell % GRID_W;
        state->food_y = cell / GRID_W;

        struct event event = {.x = 0, .y = GRID_H / 2, .color = color_snake};
        bpf_map_push_elem(&render_events, &event, 0);

        event = (struct event){.x = state->food_x, .y = state->food_y, .color = color_food};
        bpf_map_push_elem(&render_events, &event, 0);

        return 0;
    } else {
        state->snake.dir = dir;
        return update_position(state, cell);
    }
}
