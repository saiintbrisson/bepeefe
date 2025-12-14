use bepeefe::{
    object::{EbpfObject, Val},
    vm::Vm,
};

fn main() {
    const FILE: &[u8] = include_bytes!("./bpf/sum_primes.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let mut vm = Vm::new();
    let prog = vm.prepare(prog, bepeefe::vm::MapReuseStrategy::None);

    let ctx = prog.build_ctx(&[Val::Number(100_000)]);
    vm.run(&prog, &ctx);

    eprintln!("result = {}", vm.registers[0] as i64);
}
