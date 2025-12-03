use bepeefe::{
    loader::{Program, Val},
    vm::Vm,
};

fn main() {
    const FILE: &[u8] = include_bytes!("./bpf/map_hash.o");
    let program = Program::from_object(&FILE);

    let func = program.resolve_function("entry").unwrap();

    let mut vm = Vm::new(program);

    for stream_id in 1..20 {
        for len in 0..stream_id {
            let entry = func.build_entrypoint(
                &[
                    ("stream_id", Val::Number(stream_id)),
                    ("len", Val::Number(len)),
                ]
                .into(),
            );

            vm.run(entry);
        }
    }

    eprintln!("result = {}", vm.registers[0] as i32);
}
