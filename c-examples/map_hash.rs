use bepeefe::{EbpfObject, Value, Vm, verifier::VerifierConfig, vm::MapReuseStrategy};

fn main() {
    const FILE: &[u8] = include_bytes!("map_hash.o");
    let obj = EbpfObject::from_elf(&FILE).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let vm = Vm::new();
    let prog = vm
        .prepare(prog, MapReuseStrategy::None, &VerifierConfig::default())
        .unwrap();

    let mut r0 = 0u64;
    for stream_id in 1..20 {
        for len in 0..stream_id {
            let image = prog
                .build_image(&[Value::from([
                    ("stream_id", Value::Number(stream_id)),
                    ("len", Value::Number(len)),
                ])])
                .unwrap();

            r0 = prog.run(image, None);
        }
    }

    eprintln!("result = {}", r0 as i32);
}
