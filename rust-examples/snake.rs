#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

const GRID_W: usize = 32;
const GRID_H: usize = 32;
const DIE: i64 = -1;

#[repr(u8)]
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "bpf"), derive(serde::Serialize))]
enum Direction {
    Up = 0,
    Right = 1,
    Down = 2,
    Left = 3,
}

#[repr(C)]
#[cfg_attr(not(target_arch = "bpf"), derive(serde::Serialize))]
struct TickCtx {
    dir: Direction,
}

#[repr(u8)]
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "bpf"), derive(serde::Deserialize))]
enum RenderEventType {
    Clear = 0,
    Snake = 1,
    Food = 2,
}

#[repr(C)]
#[cfg_attr(not(target_arch = "bpf"), derive(serde::Deserialize))]
struct RenderEvent {
    x: u8,
    y: u8,
    ty: RenderEventType,
}

#[cfg(target_arch = "bpf")]
mod program {
    use core::{ffi::c_void, hint::black_box};
    use rust_examples::{
        BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_STACK, bpf_get_prandom_u32, bpf_map_lookup_elem,
        bpf_map_push_elem, decl_map,
    };

    use super::{DIE, Direction, GRID_H, GRID_W, RenderEvent, RenderEventType, TickCtx};

    #[repr(C)]
    struct Snake {
        dir: Direction,
        len: u8,
        head: u8,
        body: [u16; 64],
    }

    #[repr(C)]
    struct Game {
        snake: Snake,
        food_x: u8,
        food_y: u8,
        grid: [u8; GRID_W * GRID_H / 8],
    }

    decl_map!(state_map {
        r#type: BPF_MAP_TYPE_ARRAY,
        key: u32,
        value: Game,
        max_entries: 1,
    });

    decl_map!(render_events {
        r#type: BPF_MAP_TYPE_STACK,
        value: RenderEvent,
        max_entries: 1024,
    });

    macro_rules! die_if {
        ($cond:expr) => {
            if black_box($cond) {
                return DIE;
            }
        };
    }

    fn push_event(x: u8, y: u8, ty: RenderEventType) {
        let event = RenderEvent { x, y, ty };
        unsafe {
            bpf_map_push_elem(
                &render_events as *const _ as *const c_void,
                &event as *const _ as *const c_void,
                0,
            );
        }
    }

    fn update_position(state: &mut Game, cell: u32) -> i64 {
        let head = state.snake.head as usize;
        if head >= state.snake.body.len() {
            return DIE;
        }

        let cur = state.snake.body[head];
        let mut nx = (cur & 0xFF) as i16;
        let mut ny = (cur >> 8) as i16;

        match state.snake.dir {
            Direction::Up => ny += 1,
            Direction::Right => nx += 1,
            Direction::Down => ny -= 1,
            Direction::Left => nx -= 1,
            _ => return DIE,
        }
        die_if!(nx < 0 || ny < 0 || nx >= GRID_W as i16 || ny >= GRID_H as i16);

        let len = state.snake.len as usize;
        die_if!(len < 1 || len >= state.snake.body.len());

        let grid_cell = ny as usize * GRID_W + nx as usize;
        let byte_idx = grid_cell >> 3;
        let bit = 1u8 << (grid_cell & 7);
        die_if!(byte_idx >= state.grid.len());

        let ev_x;
        let ev_y;
        let ev_type;

        if nx == state.food_x as i16 && ny == state.food_y as i16 {
            die_if!(state.grid[byte_idx] & bit != 0);

            state.snake.len = (len + 1) as u8;
            state.food_x = (cell % GRID_W as u32) as u8;
            state.food_y = (cell / GRID_W as u32) as u8;

            ev_x = state.food_x;
            ev_y = state.food_y;
            ev_type = RenderEventType::Food;
        } else {
            let mut tail_idx = head + state.snake.body.len() + 1 - len;

            if black_box(tail_idx >= state.snake.body.len()) {
                tail_idx -= state.snake.body.len();
            }

            die_if!(tail_idx >= state.snake.body.len());

            let tail = state.snake.body[tail_idx];
            let tc = (tail >> 8) as usize * GRID_W + (tail & 0xFF) as usize;
            let tb = black_box(tc >> 3);
            die_if!(tb >= state.grid.len());

            state.grid[tb] &= !(1u8 << (tc & 7));

            die_if!(state.grid[byte_idx] & bit != 0);

            ev_x = (tail & 0xFF) as u8;
            ev_y = (tail >> 8) as u8;
            ev_type = RenderEventType::Clear;
        }

        state.grid[byte_idx] |= bit;

        let mut new_head = head + 1;
        if new_head >= state.snake.body.len() {
            new_head = 0;
        }

        state.snake.body[new_head] = (nx as u16 & 0xFF) | ((ny as u16) << 8);
        state.snake.head = new_head as u8;

        push_event(ev_x, ev_y, ev_type);
        push_event(nx as u8, ny as u8, RenderEventType::Snake);

        (state.snake.len - 1) as i64
    }

    #[unsafe(no_mangle)]
    fn on_tick(ctx: &TickCtx) -> i64 {
        let dir = ctx.dir;
        let cell = unsafe { bpf_get_prandom_u32() } % (GRID_W as u32 * GRID_H as u32);

        let idx: u32 = 0;
        let state_ptr = unsafe {
            bpf_map_lookup_elem(
                &state_map as *const _ as *const c_void,
                &idx as *const _ as *const c_void,
            )
        };
        die_if!(state_ptr.is_null());

        let state = unsafe { &mut *(state_ptr as *mut Game) };

        if state.snake.len == 0 {
            state.snake.dir = Direction::Right;
            state.snake.len = 1;
            state.snake.head = 0;
            state.snake.body[0] = ((GRID_H as u16) / 2) << 8;

            let c = (GRID_H / 2) * GRID_W;
            let b = c >> 3;
            if b < state.grid.len() {
                state.grid[b] |= 1 << (c & 7);
            }

            state.food_x = (cell % GRID_W as u32) as u8;
            state.food_y = (cell / GRID_W as u32) as u8;

            push_event(0, (GRID_H / 2) as u8, RenderEventType::Snake);
            push_event(state.food_x, state.food_y, RenderEventType::Food);

            0
        } else {
            state.snake.dir = dir;
            update_position(state, cell)
        }
    }
}

#[cfg(not(target_arch = "bpf"))]
fn main() {
    use std::io::{Write, stdout};
    use std::time::Duration;

    use bepeefe::{
        EbpfObject, Vm,
        verifier::VerifierConfig,
        vm::{HostEnv, MapReuseStrategy},
    };
    use crossterm::{
        ExecutableCommand, cursor, event,
        terminal::{self, ClearType},
    };

    const PROGRAM: &[u8] =
        include_bytes!(concat!(env!("BPF_OUT_DIR"), "/", env!("CARGO_BIN_NAME")));

    let obj = EbpfObject::from_elf(PROGRAM).unwrap();
    let prog = obj.load_prog("on_tick").unwrap();

    let vm = Vm::new();
    let prog = vm
        .prepare(prog, MapReuseStrategy::None, &VerifierConfig::default())
        .unwrap();

    let mut grid = [[' '; GRID_W]; GRID_H];
    let mut dir = Direction::Right;
    let mut score = 0;
    let mut stdout = stdout();

    terminal::enable_raw_mode().unwrap();
    let _raw_guard = RawGuard;

    loop {
        if event::poll(Duration::ZERO).unwrap_or(false) {
            if let event::Event::Key(key) = event::read().unwrap() {
                if key.code == event::KeyCode::Char('c')
                    && key.modifiers.contains(event::KeyModifiers::CONTROL)
                {
                    break;
                }
                match key.code {
                    event::KeyCode::Up | event::KeyCode::Char('w') => dir = Direction::Up,
                    event::KeyCode::Down | event::KeyCode::Char('s') => dir = Direction::Down,
                    event::KeyCode::Left | event::KeyCode::Char('a') => dir = Direction::Left,
                    event::KeyCode::Right | event::KeyCode::Char('d') => dir = Direction::Right,
                    _ => {}
                }
            }
        }

        let image = prog.build_image(&[TickCtx { dir }]).unwrap();
        let new_score = prog.run(image, HostEnv::default(), None) as i64;

        let mut map = vm.map("render_events").unwrap();
        while let Some(ev) = map.pop::<RenderEvent>().unwrap() {
            grid[ev.y as usize][ev.x as usize] = match ev.ty {
                RenderEventType::Clear => ' ',
                RenderEventType::Snake => '#',
                RenderEventType::Food => '*',
            };
        }

        stdout.execute(terminal::Clear(ClearType::All)).unwrap();
        stdout.execute(cursor::MoveTo(0, 0)).unwrap();

        let border = "-".repeat(GRID_W);
        write!(stdout, "+{border}+\r\n").unwrap();
        for row in grid.iter().rev() {
            write!(stdout, "|").unwrap();
            for &cell in row {
                write!(stdout, "{cell}").unwrap();
            }
            write!(stdout, "|\r\n").unwrap();
        }
        write!(stdout, "+{border}+\r\n").unwrap();
        write!(stdout, "score: {score} - use w/a/s/d/arrows to move\r\n").unwrap();
        stdout.flush().unwrap();

        if new_score == DIE {
            write!(stdout, "you died!\r\n").unwrap();
            break;
        } else {
            score = new_score;
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(not(target_arch = "bpf"))]
struct RawGuard;

#[cfg(not(target_arch = "bpf"))]
impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}
