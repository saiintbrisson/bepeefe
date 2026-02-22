use bepeefe::{EbpfObject, ProgramValue, Vm, vm::MapReuseStrategy};

fn main() {
    const FILE: &[u8] = include_bytes!("sum_primes.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let vm = Vm::new();
    let prog = vm.prepare(prog, MapReuseStrategy::None);

    let ctx = prog.build_ctx(&[ProgramValue::Number(100_000)]);
    let r0 = prog.run(&ctx);

    eprintln!("result = {}", r0 as i64);
}
