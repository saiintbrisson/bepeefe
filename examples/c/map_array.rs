use bepeefe::{EbpfObject, ProgramValue, Vm, vm::MapReuseStrategy};

fn main() {
    const FILE: &[u8] = include_bytes!("map_array.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let mut vm = Vm::new();
    let prog = vm.prepare(prog, MapReuseStrategy::None);

    let init_kbs = ProgramValue::Number(3070);
    let local_port = ProgramValue::Number(3000);

    let mut map = vm.map("port_map");
    map.update(&local_port, &init_kbs).unwrap();

    let ctx = prog.build_ctx(&[ProgramValue::from([
        ("local_port", local_port.clone()),
        ("len", ProgramValue::Number(3)),
    ])]);
    vm.run(&prog, &ctx);

    eprintln!("result = {}", vm.registers[0] as i32);
}
