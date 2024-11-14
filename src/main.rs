#![feature(alloc_layout_extra)]

// mod bpf_prog;
mod isa;
mod maps;
mod program;
mod vm;

fn main() {
    let mut args = std::env::args().skip(1);
    let file = args.next().unwrap();
    let entry = args.next().unwrap();

    let file = std::fs::read(file).unwrap();
    let program = program::load_object(file, &entry);

    let mut vm = vm::Vm::new(program);

    let code: Vec<_> = vm
        .program
        .code
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

    while !vm.exit {
        let pc = vm.program_counter as usize;

        let Some(&instruction) = code.get(pc) else {
            eprintln!("no PC at {}", vm.program_counter);
            break;
        };

        vm.program_counter += 1;

        let op = instruction & 0xFF;

        let name = isa::INSTRUCTION_NAME_TABLE[op as usize];
        let dst = (instruction >> 8) & 0xF;
        let src = (instruction >> 12) & 0xF;
        let imm = (instruction >> 32) as i32;
        let offset = (instruction >> 16) as i16;
        eprintln!("insn @ {:>2}: {name:<14} ({op:02X?}), src: {src:>2}, dst: {dst:>2}, offset: {offset:>5}, imm: {imm:08X?} ({imm:>5}) ({instruction:016X?})", vm.program_counter - 1);

        let next = code.get(pc + 1).copied();
        isa::INSTRUCTION_TABLE[op as usize](&mut vm, instruction, next);
    }

    eprintln!("result = {}", vm.registers[0] as i32);
}
