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
        eprintln!(
            "{idx:>2}: {name:<14} ({op:02X?}), src: {src:>2}, dst: {dst:>2}, offset: {offset:>5}, imm: {imm:08X?} ({imm:>5}) ({insn:016X?})",
            name = isa::INSTRUCTION_NAME_TABLE[insn.opcode() as usize],
            op = insn.opcode(),
            dst = insn.dst_reg(),
            src = insn.src_reg(),
            imm = insn.imm(),
            offset = insn.offset(),
            insn = insn.0
        );
    }

    while !vm.exit {
        let Some(insn) = vm.code.next() else {
            panic!();
        };

        eprintln!(
            "insn @ {pc:>2}: {name:<14} ({op:02X?}), src: {src:>2}, dst: {dst:>2}, offset: {offset:>5}, imm: {imm:08X?} ({imm:>5}) ({insn:016X?})",
            pc = vm.code.pc(),
            name = isa::INSTRUCTION_NAME_TABLE[insn.opcode() as usize],
            op = insn.opcode(),
            dst = insn.dst_reg(),
            src = insn.src_reg(),
            imm = insn.imm(),
            offset = insn.offset(),
            insn = insn.0
        );

        isa::INSTRUCTION_TABLE[insn.opcode() as usize](&mut vm, insn);
    }

    eprintln!("result = {}", vm.registers[0] as i32);
}
