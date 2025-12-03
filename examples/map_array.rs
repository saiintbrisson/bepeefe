use bepeefe::{
    loader::{Program, Val},
    vm::Vm,
};

fn main() {
    const FILE: &[u8] = include_bytes!("./bpf/map_array.o");
    let program = Program::from_object(&FILE);

    let entrypoint = program
        .build_entrypoint(
            "entry",
            &[("local_port", Val::Number(3000)), ("len", Val::Number(15))].into(),
        )
        .expect("failed to build entrypoint");
    let mut vm = Vm::new(program);

    let init_kbs = 3070u64;
    let local_port = 3000u32;

    vm.map_by_name("port_map")
        .unwrap()
        .repr
        .update(&local_port.to_ne_bytes(), &init_kbs.to_ne_bytes())
        .unwrap();

    vm.run(entrypoint);
    eprintln!("result = {}", vm.registers[0] as i32);
}
