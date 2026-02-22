use bepeefe::{EbpfObject, ProgramValue, Vm, vm::MapReuseStrategy};

fn main() {
    const FILE: &[u8] = include_bytes!("map_hash.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let mut vm = Vm::new();
    let prog = vm.prepare(prog, MapReuseStrategy::None);

    for stream_id in 1..20 {
        for len in 0..stream_id {
            let ctx = prog.build_ctx(&[ProgramValue::from([
                ("stream_id", ProgramValue::Number(stream_id)),
                ("len", ProgramValue::Number(len)),
            ])]);

            vm.run(&prog, &ctx);
        }
    }

    eprintln!("result = {}", vm.registers[0] as i32);
}
