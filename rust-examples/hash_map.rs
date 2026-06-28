#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[repr(C)]
#[cfg_attr(not(target_arch = "bpf"), derive(serde::Serialize))]
struct Ctx {
    id: u32,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[repr(C)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug, serde::Deserialize))]
struct PacketStats {
    tx_bytes: u64,
    rx_bytes: u64,
}

#[cfg(target_arch = "bpf")]
mod program {
    use core::ffi::c_void;
    use rust_examples::{BPF_MAP_TYPE_HASH, bpf_map_lookup_elem, bpf_map_update_elem, decl_map};

    use super::{Ctx, PacketStats};

    decl_map!(counters {
        r#type: BPF_MAP_TYPE_HASH,
        key: u32,
        value: PacketStats,
        max_entries: 64,
    });

    #[unsafe(no_mangle)]
    fn entry(ctx: &Ctx) -> u64 {
        let map = &counters as *const _ as *const c_void;
        let key_ptr = &ctx.id as *const _ as *const c_void;

        let val = unsafe { bpf_map_lookup_elem(map, key_ptr) };
        if !val.is_null() {
            let stats = unsafe { &mut *(val as *mut PacketStats) };
            stats.tx_bytes += ctx.tx_bytes;
            stats.rx_bytes += ctx.rx_bytes;
        } else {
            let new = PacketStats {
                tx_bytes: ctx.tx_bytes,
                rx_bytes: ctx.rx_bytes,
            };
            unsafe {
                bpf_map_update_elem(map, key_ptr, &new as *const _ as *const c_void, 0);
            }
        }

        0
    }
}

#[cfg(not(target_arch = "bpf"))]
fn main() {
    use bepeefe::{EbpfObject, Vm, verifier::VerifierConfig, vm::MapReuseStrategy};
    use std::thread;

    const PROGRAM: &[u8] =
        include_bytes!(concat!(env!("BPF_OUT_DIR"), "/", env!("CARGO_BIN_NAME")));

    let obj = EbpfObject::from_elf(PROGRAM).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let vm = Vm::new();
    let handle = vm
        .prepare(
            prog,
            MapReuseStrategy::MatchByName,
            &VerifierConfig::default(),
        )
        .unwrap();

    let threads: Vec<_> = (0..4u32)
        .map(|t| {
            let handle = handle.clone();
            thread::spawn(move || {
                for id in 1..=16u32 {
                    let image = handle
                        .build_image(&[Ctx {
                            id,
                            tx_bytes: (t as u64 + 1) * 10,
                            rx_bytes: (t as u64 + 1) * 20,
                        }])
                        .unwrap();
                    handle.run(image, None);
                }
            })
        })
        .collect();

    for t in threads {
        t.join().unwrap();
    }

    let counters = vm.map("counters").unwrap();
    for id in 1u32..=16 {
        let stats: PacketStats = counters.lookup(&id).unwrap().unwrap();
        assert_eq!(stats.tx_bytes, 100, "id {id} tx mismatch");
        assert_eq!(stats.rx_bytes, 200, "id {id} rx mismatch");
        eprintln!("counters[{id}] = {stats:?}");
    }

    eprintln!("all 16 ids verified");
}
