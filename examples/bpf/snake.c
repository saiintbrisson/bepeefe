#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_LEN 64
#define GRID_W 64
#define GRID_H 16
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
    __u16 body[MAX_LEN];
};

struct game {
    struct snake snake;
    __u8 food_x;
    __u8 food_y;
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
    __u16 cur = state->snake.body[0];
    __s16 nx = get_x(cur);
    __s16 ny = get_y(cur);

    switch (state->snake.dir) {
      case up:    ny++; break;
      case right: nx++; break;
      case down:  ny--; break;
      case left:  nx--; break;
      default:    DIE;
    };

    if (nx < 0 ||  ny < 0 || nx >= GRID_W || ny >= GRID_H)
        DIE;

    __u64 len = (__u64) state->snake.len;
    if (len < 1 || len >= MAX_LEN) DIE;

    __u8 ev_x, ev_y;
    enum color ev_color;

    cur = state->snake.body[len - 1];
    if (nx == state->food_x && ny == state->food_y) {
      state->snake.body[len] = cur;
      state->snake.len = ++len;
      state->food_x = rand % GRID_W;
      state->food_y = rand / GRID_W;
      ev_x = state->food_x; ev_y = state->food_y; ev_color = color_food;
    } else {
      ev_x = get_x(cur); ev_y = get_y(cur); ev_color = color_clear;
    }

    __u16 new = (__u16) to_pos(nx, ny);
    __u16 *ptr = state->snake.body + len - 1;
    if (len == 1) goto skip;
    do {
        cur = *(ptr - 1);
        if (cur == new) DIE;
        *ptr = cur;
        ptr--;
    } while (--len > 1);
    skip:
    *ptr = new;

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
        state->snake.len = 1;
        state->snake.dir = right;
        state->snake.body[0] = to_pos(0, GRID_H / 2);

        state->food_x = cell % GRID_W;
        state->food_y = cell / GRID_W;

        struct event event = {.x = 0, .y = GRID_H / 2, .color = color_snake};
        bpf_map_push_elem(&render_events, &event, 0);

        event = (struct event) {.x = state->food_x, .y = state->food_y, .color = color_food};
        bpf_map_push_elem(&render_events, &event, 0);

        return 0;
    } else {
        state->snake.dir = dir;
        return update_position(state, cell);
    }
}
