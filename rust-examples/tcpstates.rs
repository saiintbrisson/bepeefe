#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
#![cfg_attr(target_arch = "bpf", no_builtins)]

use core::ffi::c_void;

const TASK_COMM_LEN: usize = 16;
const IPPROTO_TCP: u16 = 6;
const AF_INET: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug, serde::Serialize))]
enum TcpState {
    Established = 1,
    SynSent = 2,
    FinWait1 = 4,
    #[default]
    Close = 7,
}

#[repr(C)]
#[cfg_attr(not(target_arch = "bpf"), derive(serde::Serialize))]
struct InetSockSetState {
    ent: [u8; 8],
    #[cfg_attr(not(target_arch = "bpf"), serde(serialize_with = "skaddr_as_u64"))]
    skaddr: *const c_void,
    oldstate: TcpState,
    newstate: TcpState,
    sport: u16,
    dport: u16,
    family: u16,
    protocol: u16,
    saddr: [u8; 4],
    daddr: [u8; 4],
    saddr_v6: [u8; 16],
    daddr_v6: [u8; 16],
}

#[cfg(not(target_arch = "bpf"))]
fn skaddr_as_u64<S: serde::Serializer>(v: &*const c_void, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(*v as u64)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug))]
struct Event {
    saddr: [u8; 16],
    daddr: [u8; 16],
    skaddr: *const c_void,
    ts_us: u64,
    delta_us: u64,
    pid: u32,
    oldstate: TcpState,
    newstate: TcpState,
    family: u16,
    sport: u16,
    dport: u16,
    task: [u8; TASK_COMM_LEN],
}

#[cfg(target_arch = "bpf")]
mod program {
    // SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
    // Copyright (c) 2021 Hengqi Chen
    //
    // Ref: <https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/14-tcpstates/tcpstates.bpf.c>

    use core::ffi::c_void;
    use core::mem::size_of;
    use rust_examples::{
        BPF_F_CURRENT_CPU, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERF_EVENT_ARRAY, bpf_get_current_comm,
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_map_delete_elem, bpf_map_lookup_elem,
        bpf_map_update_elem, bpf_perf_event_output, decl_map,
    };

    use super::{Event, IPPROTO_TCP, InetSockSetState, TASK_COMM_LEN};

    decl_map!(timestamps {
        r#type: BPF_MAP_TYPE_HASH,
        key: u64,
        value: u64,
        max_entries: 10240,
    });

    decl_map!(events {
        r#type: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
    });

    #[unsafe(no_mangle)]
    fn handle_set_state(ctx: &InetSockSetState) -> u64 {
        if ctx.protocol != IPPROTO_TCP {
            return 0;
        }

        let sk = ctx.skaddr;
        let ts = unsafe { bpf_ktime_get_ns() };

        let prev = unsafe {
            bpf_map_lookup_elem(
                &timestamps as *const _ as *const c_void,
                &sk as *const _ as *const c_void,
            )
        };
        let delta_us = if prev.is_null() {
            0
        } else {
            (ts - unsafe { *(prev as *const u64) }) / 1000
        };

        let mut event = Event {
            skaddr: sk,
            ts_us: ts / 1000,
            delta_us: delta_us,
            pid: (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32,
            oldstate: ctx.oldstate,
            newstate: ctx.newstate,
            family: ctx.family,
            sport: ctx.sport,
            dport: ctx.dport,
            ..Default::default()
        };

        event.saddr[..4].copy_from_slice(&ctx.saddr);
        event.daddr[..4].copy_from_slice(&ctx.daddr);

        unsafe {
            bpf_get_current_comm(event.task.as_mut_ptr() as *mut c_void, TASK_COMM_LEN as u32);
            bpf_perf_event_output(
                ctx as *const _ as *const c_void,
                &events as *const _ as *const c_void,
                BPF_F_CURRENT_CPU,
                &event as *const _ as *const c_void,
                size_of::<Event>() as u64,
            );
        }

        if matches!(ctx.newstate, super::TcpState::Close) {
            unsafe {
                bpf_map_delete_elem(
                    &timestamps as *const _ as *const c_void,
                    &sk as *const _ as *const c_void,
                );
            }
        } else {
            unsafe {
                bpf_map_update_elem(
                    &timestamps as *const _ as *const c_void,
                    &sk as *const _ as *const c_void,
                    &ts as *const _ as *const c_void,
                    0,
                );
            }
        }

        0
    }
}

#[cfg(not(target_arch = "bpf"))]
fn main() {
    use bepeefe::{
        EbpfObject, Vm,
        capture::{Capture, Event as CapEvent},
        verifier::VerifierConfig,
        vm::{HostEnv, MapReuseStrategy},
    };
    use std::sync::{Arc, Mutex};

    const PROGRAM: &[u8] =
        include_bytes!(concat!(env!("BPF_OUT_DIR"), "/", env!("CARGO_BIN_NAME")));

    struct EventSink(Mutex<Vec<Event>>);
    impl Capture for EventSink {
        fn record(&self, event: CapEvent<'_>) {
            if let CapEvent::PerfEventOutput { data, .. } = event
                && data.len() == std::mem::size_of::<Event>()
            {
                let evt = unsafe { (data.as_ptr() as *const Event).read_unaligned() };
                self.0.lock().unwrap().push(evt);
            }
        }
    }

    let obj = EbpfObject::from_elf(PROGRAM).unwrap();
    let prog = obj.load_prog("handle_set_state").unwrap();
    let vm = Vm::new();
    let prog = vm
        .prepare(prog, MapReuseStrategy::None, &VerifierConfig::default())
        .unwrap();

    let sink = Arc::new(EventSink(Mutex::new(Vec::new())));

    let transitions = &[
        (TcpState::Close, TcpState::SynSent, 0),
        (TcpState::SynSent, TcpState::Established, 30_000_000),
        (TcpState::Established, TcpState::FinWait1, 1_500_000_000),
        (TcpState::FinWait1, TcpState::Close, 1_550_000_000),
    ];

    let base_ktime = 1_000_000_000u64;
    for &(old, new, delta) in transitions {
        let ctx = InetSockSetState {
            ent: [0; 8],
            skaddr: 0xDEADBEEF as *const _,
            oldstate: old,
            newstate: new,
            sport: 12345,
            dport: 80,
            family: AF_INET,
            protocol: IPPROTO_TCP,
            saddr: [10, 0, 0, 1],
            daddr: [127, 0, 0, 1],
            saddr_v6: [0; 16],
            daddr_v6: [0; 16],
        };
        let env = HostEnv {
            ktime_ns: base_ktime + delta,
            pid: 1337,
            tgid: 7331,
            comm: Arc::from("curl"),
            ..HostEnv::default()
        };
        let image = prog.build_image(&[ctx]).unwrap();
        prog.run(image, env, Some(sink.clone()));
    }

    for evt in sink.0.lock().unwrap().iter() {
        let sa = &evt.saddr[..4];
        let da = &evt.daddr[..4];
        let comm = std::str::from_utf8(&evt.task)
            .unwrap_or("?")
            .trim_end_matches('\0');
        println!(
            "{old:?} -> {new:?}  delta={delta} us  {sa:?}:{sp} -> {da:?}:{dp}  pid={pid} comm={comm}",
            old = evt.oldstate,
            new = evt.newstate,
            delta = evt.delta_us,
            sp = evt.sport,
            dp = evt.dport,
            pid = evt.pid,
        );
    }
}
