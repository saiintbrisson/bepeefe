use bepeefe::{
    EbpfObject, Value, Vm,
    verifier::VerifierConfig,
    vm::{HostEnv, MapReuseStrategy},
};

fn main() {
    const FILE: &[u8] = include_bytes!("map_array.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let vm = Vm::new();
    let prog = vm
        .prepare(prog, MapReuseStrategy::None, &VerifierConfig::default())
        .unwrap();

    let init_kbs = Value::Number(3070);
    let local_port = Value::Number(3000);

    let map = vm.map("port_map").unwrap();
    map.update(&local_port, &init_kbs).unwrap();

    let image = prog
        .build_image(&[Value::from([
            ("local_port", local_port.clone()),
            ("len", Value::Number(3)),
        ])])
        .unwrap();
    let r0 = prog.run(image, HostEnv::default(), None);

    eprintln!("result = {}", r0 as i32);
}
