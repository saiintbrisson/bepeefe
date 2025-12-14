use bepeefe::{
    object::{EbpfObject, Val},
    vm::Vm,
};

fn main() {
    const FILE: &[u8] = include_bytes!("./bpf/map_array.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let mut vm = Vm::new();
    let prog = vm.prepare(prog, bepeefe::vm::MapReuseStrategy::None);

    let init_kbs = Val::Number(3070);
    let local_port = Val::Number(3000);

    let mut map = vm.map("port_map");
    map.update(&local_port, &init_kbs).unwrap();

    let ctx =
        prog.build_ctx(&[[("local_port", local_port.clone()), ("len", Val::Number(1))].into()]);
    vm.run(&prog, &ctx);

    eprintln!("result = {}", vm.registers[0] as i32);
}
