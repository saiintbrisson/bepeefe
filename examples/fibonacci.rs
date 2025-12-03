use bepeefe::{
    loader::{Program, Val},
    vm::Vm,
};

fn main() {
    const FILE: &[u8] = include_bytes!("./bpf/fibonacci.o");
    let program = Program::from_object(&FILE);

    let entrypoint = program
        .build_entrypoint("fibonacci", &Val::Number(2))
        .expect("failed to build entrypoint");
    let mut vm = Vm::new(program);
    vm.run(entrypoint);

    eprintln!("result = {}", vm.registers[0] as i64);
}
