#![feature(debug_closure_helpers)]

mod isa;
mod loader;

fn main() {
    let mut args = std::env::args().skip(1);
    let file = args.next().unwrap();
    let entry = args.next().unwrap();

    let (prog, main) = loader::load_elf(&file, entry.as_bytes());

    let code: Vec<_> = prog
        .chunks_exact(8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        .collect();

    for (idx, insn) in code.iter().enumerate() {
        let op = insn & 0xFF;

        let name = isa::INSTRUCTION_NAME_TABLE[op as usize];
        let dst = (insn >> 8) & 0xF;
        let src = (insn >> 12) & 0xF;
        let imm = (insn >> 32) as i32;
        let offset = (insn >> 16) as i16;
        eprintln!("{idx:>2}: {name:<14} ({op:02X?}), src: {src:>2}, dst: {dst:>2}, offset: {offset:>5}, imm: {imm:08X?} ({imm:>5}) ({insn:016X?})");
    }

    let mut state = State {
        code,
        registers: Default::default(),
        program_counter: main as i32,
        stack: Default::default(),
        call_stack: Vec::with_capacity(1),
        exit: false,
    };

    state.registers[10] = 512;
    state.stack = vec![0; 512];

    while !state.exit {
        let pc = state.program_counter as usize;

        let Some(&instruction) = state.code.get(pc) else {
            eprintln!("no PC at {}", state.program_counter);
            break;
        };

        state.program_counter += 1;

        let op = instruction & 0xFF;

        let name = isa::INSTRUCTION_NAME_TABLE[op as usize];
        let dst = (instruction >> 8) & 0xF;
        let src = (instruction >> 12) & 0xF;
        let imm = (instruction >> 32) as i32;
        let offset = (instruction >> 16) as i16;
        eprintln!("insn @ {:>2}: {name:<14} ({op:02X?}), src: {src:>2}, dst: {dst:>2}, offset: {offset:>5}, imm: {imm:08X?} ({imm:>5}) ({instruction:016X?})", state.program_counter - 1);

        let next = state.code.get(pc + 1).copied();
        isa::INSTRUCTION_TABLE[op as usize](&mut state, instruction, next);
    }

    dbg!(&state);
    eprintln!("result = {}", state.registers[0] as i32);
}

pub struct State {
    code: Vec<u64>,
    program_counter: i32,

    registers: [u64; 11],
    stack: Vec<u8>,

    call_stack: Vec<CallStackEntry>,

    exit: bool,
}

#[derive(Debug)]
pub struct CallStackEntry {
    /// Registers preserved between calls, R6 to R9.
    registers: [u64; 4],
    caller: i32,
    stack_size: usize,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registers = |f: &mut std::fmt::Formatter<'_>| {
            let mut registers = f.debug_struct("Registers");
            for (idx, val) in self.registers.iter().enumerate() {
                registers.field(&format!("r{idx:<2}"), &format_args!("{val:016?}"));
            }
            registers.finish()
        };

        let stack = |f: &mut std::fmt::Formatter<'_>| {
            let mut list = f.debug_list();
            for chunk in self.stack.chunks(16) {
                list.entry_with(|f| {
                    Ok(for b in chunk {
                        f.write_fmt(format_args!("{b:02X?} "))?;
                    })
                });
            }
            list.finish()
        };

        f.debug_struct("State")
            .field_with("registers", registers)
            .field("program_counter", &self.program_counter)
            .field("call_stack", &self.call_stack)
            .field_with("stack", stack)
            .field("exit", &self.exit)
            .finish()
    }
}
