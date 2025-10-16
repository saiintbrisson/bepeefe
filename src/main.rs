// #![feature(alloc_layout_extra)]

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

    for (idx, insn) in vm.code.code().iter().enumerate() {
        let op = insn & 0xFF;

        let name = isa::INSTRUCTION_NAME_TABLE[op as usize];
        let dst = (insn >> 8) & 0xF;
        let src = (insn >> 12) & 0xF;
        let imm = (insn >> 32) as i32;
        let offset = (insn >> 16) as i16;
        eprintln!(
            "{idx:>2}: {name:<14} ({op:02X?}), src: {src:>2}, dst: {dst:>2}, offset: {offset:>5}, imm: {imm:08X?} ({imm:>5}) ({insn:016X?})"
        );
    }

    while !vm.exit {
        let Some(instruction) = vm.code.next() else {
            panic!();
        };

        let op = instruction & 0xFF;

        let name = isa::INSTRUCTION_NAME_TABLE[op as usize];
        let dst = (instruction >> 8) & 0xF;
        let src = (instruction >> 12) & 0xF;
        let imm = (instruction >> 32) as i32;
        let offset = (instruction >> 16) as i16;
        eprintln!(
            "insn @ {:>2}: {name:<14} ({op:02X?}), src: {src:>2}, dst: {dst:>2}, offset: {offset:>5}, imm: {imm:08X?} ({imm:>5}) ({instruction:016X?})",
            vm.code.pc()
        );

        isa::INSTRUCTION_TABLE[op as usize](&mut vm, instruction);
    }

    eprintln!("result = {}", vm.registers[0] as i32);
}
