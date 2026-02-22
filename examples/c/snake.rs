use std::io::{Write, stdout};
use std::time::Duration;

use bepeefe::{EbpfObject, ProgramValue, Vm, vm::MapReuseStrategy};
use crossterm::{
    ExecutableCommand,
    cursor, event,
    terminal::{self, ClearType},
};
use rand::Rng;

const GRID_W: usize = 64;
const GRID_H: usize = 16;
const DIE: i32 = -1;

fn main() {
    const FILE: &[u8] = include_bytes!("snake.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();

    let prog = obj.load_prog("on_tick").unwrap();

    let mut vm = Vm::new();
    let prog = vm.prepare(prog, MapReuseStrategy::None);

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

        let ctx = prog.build_ctx(&[ProgramValue::from([
            ("dir", ProgramValue::Number(dir as u8 as i64)),
            (
                "rand",
                ProgramValue::Number(rand::rng().random::<i32>() as _),
            ),
        ])]);
        vm.run(&prog, &ctx);

        let mut map = vm.map("render_events");
        while let Some(ProgramValue::Map(ev)) = map.pop::<ProgramValue>() {
            let (&ProgramValue::Number(color), &ProgramValue::Number(x), &ProgramValue::Number(y)) = (
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
        write!(stdout, "score: {score} - use arrows to move\r\n").unwrap();
        stdout.flush().unwrap();

        if new_score == DIE {
            write!(stdout, "you died!\r\n").unwrap();
            break;
        } else {
            score = new_score;
        }

        let delay = match dir {
            Direction::Left | Direction::Right => 100,
            _ => 200,
        };
        std::thread::sleep(Duration::from_millis(delay));
    }
}

struct RawGuard;

impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
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
