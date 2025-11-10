use std::alloc::Layout;

use bepeefe::{
    isa,
    loader::{Program, Val},
    vm::Vm,
};

fn main() {
    let file = std::fs::read("./examples/bpf/map_array.o").unwrap();
    let program = Program::from_object(&file);

    let entrypoint = program
        .build_entrypoint(
            "entry",
            &[("local_port", Val::Number(3000)), ("len", Val::Number(3))],
        )
        .expect("failed to build entrypoint");
    let mut vm = Vm::new_with_entrypoint(program, entrypoint);

    let init_kbs = 3070u64;
    let local_port = 3000u32;

    let val = vm.mem.alloc_layout(Layout::new::<u64>()).unwrap();
    vm.mem
        .write(val.guest_addr(), &init_kbs.to_ne_bytes())
        .unwrap();

    vm.map_by_name("port_map")
        .unwrap()
        .repr
        .update_elem(&local_port.to_ne_bytes(), val.as_ptr().as_ptr())
        .unwrap();

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
