use bepeefe::{
    object::{EbpfObject, Val},
    vm::{MapReuseStrategy, Vm},
};

const FILE: &[u8] = include_bytes!("./bpf/fibonacci.o");

fn main() {
    let mut vm = Vm::new();

    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("fibonacci").unwrap();
    let ctx = prog.build_ctx(&[Val::Number(8)]);

    let handle = vm.prepare(prog, MapReuseStrategy::MatchByName);
    vm.run(&handle, &ctx);

    eprintln!("result = {}", vm.registers[0] as i64);
}
