use std::io::Read;

use bepeefe::{
    object::{EbpfObject, Val},
    vm::Vm,
};
use rand::Rng;

const GRID_W: usize = 64;
const GRID_H: usize = 16;
const DIE: i32 = -1;

fn main() {
    const FILE: &[u8] = include_bytes!("./bpf/snake.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();

    let prog = obj.load_prog("on_tick").unwrap();

    let mut vm = Vm::new();
    let prog = vm.prepare(prog, bepeefe::vm::MapReuseStrategy::None);

    let mut grid = [[' '; GRID_W]; GRID_H];
    let mut dir = Direction::Right;
    let mut score = 0;

    let _raw = RawMode::enable();

    loop {
        if let Some(d) = read_arrow() {
            dir = d;
        }

        let ctx = prog.build_ctx(&[[
            ("dir", Val::Number(dir as u8 as i64)),
            ("rand", Val::Number(rand::rng().random::<i32>() as _)),
        ]
        .into()]);
        vm.run(&prog, &ctx);

        let mut map = vm.map("render_events");
        while let Some(Val::Map(ev)) = map.pop_as_val() {
            let (&Val::Number(color), &Val::Number(x), &Val::Number(y)) = (
                ev.get("color").unwrap(),
                ev.get("x").unwrap(),
                ev.get("y").unwrap(),
            ) else {
                break;
            };
            grid[y as usize][x as usize] = match color {
                0 => ' ',
                1 => '#',
                2 => '*',
                _ => unreachable!(),
            };
        }

        let new_score = vm.registers[0] as i32;

        print!("\x1b[2J\x1b[H");
        println!("+{}+", "-".repeat(GRID_W));
        for row in grid.iter().rev() {
            print!("|");
            for &cell in row {
                print!("{cell}");
            }
            println!("|");
        }
        println!("+{}+", "-".repeat(GRID_W));
        println!("score: {score}");

        if new_score == DIE {
            println!("you died!");
            break;
        } else {
            score = new_score;
        }

        let delay = match dir {
            Direction::Left | Direction::Right => 100,
            _ => 200,
        };
        std::thread::sleep(std::time::Duration::from_millis(delay));
    }
}

fn read_arrow() -> Option<Direction> {
    let mut stdin = std::io::stdin().lock();
    let mut buf = [0u8; 3];

    if stdin.read(&mut buf[..1]).ok()? == 0 {
        return None;
    }
    if buf[0] != 0x1b {
        return None;
    }
    if stdin.read(&mut buf[1..3]).ok()? < 2 {
        return None;
    }
    if buf[1] != b'[' {
        return None;
    }

    match buf[2] {
        b'A' => Some(Direction::Up),
        b'B' => Some(Direction::Down),
        b'C' => Some(Direction::Right),
        b'D' => Some(Direction::Left),
        _ => None,
    }
}

struct RawMode {
    original: libc::termios,
}

impl RawMode {
    fn enable() -> Self {
        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            libc::tcgetattr(libc::STDIN_FILENO, &mut original);

            let mut raw = original;
            raw.c_lflag &= !(libc::ICANON | libc::ECHO);
            raw.c_cc[libc::VMIN] = 0;
            raw.c_cc[libc::VTIME] = 0;
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw);

            Self { original }
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum Direction {
    Up,
    Right,
    Down,
    Left,
}
