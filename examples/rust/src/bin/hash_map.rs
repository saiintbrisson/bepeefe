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
    use guest::{BPF_MAP_TYPE_HASH, bpf_map_lookup_elem, bpf_map_update_elem, decl_map};

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

        let val = bpf_map_lookup_elem(map, key_ptr);
        if !val.is_null() {
            let stats = unsafe { &mut *(val as *mut PacketStats) };
            stats.tx_bytes += ctx.tx_bytes;
            stats.rx_bytes += ctx.rx_bytes;
        } else {
            let new = PacketStats {
                tx_bytes: ctx.tx_bytes,
                rx_bytes: ctx.rx_bytes,
            };
            bpf_map_update_elem(map, key_ptr, &new as *const _ as *const c_void, 0);
        }

        0
    }
}

#[cfg(not(target_arch = "bpf"))]
fn main() {
    use bepeefe::{EbpfObject, ProgramValue, Vm, vm::MapReuseStrategy};

    const PROGRAM: &[u8] =
        include_bytes!(concat!(env!("BPF_OUT_DIR"), "/", env!("CARGO_BIN_NAME")));

    let obj = EbpfObject::from_elf(PROGRAM).unwrap();
    let prog = obj.load_prog("entry").unwrap();

    let mut vm = Vm::new();
    let handle = vm.prepare(prog, MapReuseStrategy::MatchByName);

    let make_ctx = |id: u32, tx_bytes: u64, rx_bytes: u64| {
        handle.build_ctx(&[Ctx {
            id,
            tx_bytes,
            rx_bytes,
        }])
    };

    vm.run(&handle, &make_ctx(1, 100, 250));
    vm.run(&handle, &make_ctx(2, 50, 75));
    vm.run(&handle, &make_ctx(1, 200, 300));

    for id in [1, 2] {
        let stats: Option<PacketStats> = vm.map("counters").lookup(&id);
        eprintln!("counters[{id}] = {stats:?}");
    }
}
