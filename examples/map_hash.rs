use bepeefe::{
    object::{EbpfObject, Val},
    vm::Vm,
};

fn main() {
    const FILE: &[u8] = include_bytes!("./bpf/map_hash.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let mut vm = Vm::new();
    let prog = vm.prepare(prog, bepeefe::vm::MapReuseStrategy::None);

    for stream_id in 1..20 {
        for len in 0..stream_id {
            let ctx = prog.build_ctx(&[[
                ("stream_id", Val::Number(stream_id)),
                ("len", Val::Number(len)),
            ]
            .into()]);

            vm.run(&prog, &ctx);
        }
    }

    eprintln!("result = {}", vm.registers[0] as i32);
}
