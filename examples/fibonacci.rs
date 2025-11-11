use bepeefe::{
    isa,
    loader::{Program, Val},
    vm::Vm,
};

fn main() {
    let file = std::fs::read("./examples/bpf/fibonacci.o").unwrap();
    let program = Program::from_object(&file);

    let entrypoint = program
        .build_entrypoint("entry", &Val::Number(20))
        .expect("failed to build entrypoint");
    let mut vm = Vm::new_with_entrypoint(program, entrypoint);

    while !vm.exit {
        let Some(insn) = vm.code.next() else {
            panic!();
        };

        isa::INSTRUCTION_TABLE[insn.opcode() as usize](&mut vm, insn);
    }

    eprintln!("result = {}", vm.registers[0] as i64);
}
