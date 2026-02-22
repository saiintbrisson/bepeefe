use bepeefe::{EbpfObject, ProgramValue, Vm, vm::MapReuseStrategy};

const FILE: &[u8] = include_bytes!("fibonacci.o");

fn main() {
    let vm = Vm::new();

    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("fibonacci").unwrap();
    let ctx = prog.build_ctx(&[ProgramValue::Number(8)]);

    let handle = vm.prepare(prog, MapReuseStrategy::MatchByName);
    let r0 = handle.run(&ctx);

    eprintln!("result = {}", r0 as i64);
}
