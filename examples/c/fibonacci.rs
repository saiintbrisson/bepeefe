use bepeefe::{EbpfObject, ProgramValue, Vm, vm::MapReuseStrategy};

const FILE: &[u8] = include_bytes!("fibonacci.o");

fn main() {
    let mut vm = Vm::new();

    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("fibonacci").unwrap();
    let ctx = prog.build_ctx(&[ProgramValue::Number(8)]);

    let handle = vm.prepare(prog, MapReuseStrategy::MatchByName);
    vm.run(&handle, &ctx);

    eprintln!("result = {}", vm.registers[0] as i64);
}
