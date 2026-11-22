//! Event-stream tests for the verifier.
//!
//! Each test hand-assembles a small program, verifies it with a capturing
//! sink, and asserts the exact event sequence the walk produced alongside the
//! verification result. The stream is the contract here, so tests compare
//! full sequences rather than picking out individual events.
//!
//! Expectations are written as a tree via [`walk`], `insn!`, `branch!` and
//! `subprog!`. The tree mirrors the walk's structure: nesting replaces the
//! depth fields and the enter and exit framing events, which [`walk`]
//! reconstructs when flattening into the expected stream.
//!
//! Events reach the log by round-tripping through their JSON wire format,
//! which keeps [`RecordedEvent`] honest about what consumers actually parse.
//! A serialization change that diverges from types.ts fails every test at the
//! deserialize step, and the shape test at the bottom pins the literal JSON.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use object::SectionIndex;
use pretty_assertions::assert_eq;

use super::*;
use crate::{
    isa::mem::BPF_PSEUDO_MAP_FD,
    maps::{BPF_MAP_TYPE_HASH, BpfMap, MapRepr, MapSpec},
    object::FunctionSignature,
    verifier::event::PayloadSlot,
};

/// Owned copy of [`VerifierEvent`], produced by deserializing the event's
/// serialized form. Variant and field names must match the wire format.
#[derive(Debug, PartialEq, serde::Deserialize)]
enum RecordedEvent {
    Insn {
        depth: usize,
        pc: usize,
        read: RegMask,
        written: Vec<(u8, RegisterState)>,
    },
    BranchEnter {
        depth: usize,
        id: usize,
        target_pc: usize,
        kind: WalkOrigin,
    },
    BranchDead {
        depth: usize,
        target_pc: usize,
        kind: WalkOrigin,
    },
    StatePruned {
        depth: usize,
        fork_pc: usize,
        matched: usize,
        site: PruneSite,
    },
    BranchExit {
        depth: usize,
    },
    CallEnter {
        depth: usize,
        id: usize,
        target_pc: usize,
        name: String,
        btf_id: Option<BtfTypeId>,
        registers: Vec<RegisterState>,
    },
    CallExit {
        depth: usize,
        r0: RegisterState,
    },
    PerfEventLayout {
        depth: usize,
        pc: usize,
        map_fd: u16,
        size: Option<u32>,
        slots: Vec<PayloadSlot>,
    },
    Warning {
        pc: usize,
        message: String,
    },
}

#[derive(Default)]
struct EventLog(Mutex<Vec<RecordedEvent>>);

impl Capture for EventLog {
    fn record(&self, event: Event<'_>) {
        let Event::Verifier(event) = event else {
            return;
        };
        let json = serde_json::to_string(&event).expect("verifier event must serialize");
        let event = serde_json::from_str(&json)
            .expect("event wire format must deserialize into RecordedEvent");
        self.0.lock().expect("event log lock poisoned").push(event);
    }
}

/// One node of an expected walk tree. Bodies hold the nested walk, so depth
/// and the enter and exit framing never appear in test code, [`walk`] derives
/// them while flattening.
enum Expect {
    Insn {
        pc: usize,
        read: RegMask,
        written: Vec<(u8, RegisterState)>,
    },
    Branch {
        target_pc: usize,
        kind: WalkOrigin,
        body: Vec<Expect>,
    },
    Dead {
        target_pc: usize,
        kind: WalkOrigin,
    },
    StatePruned {
        fork_pc: usize,
        matched: usize,
        site: PruneSite,
    },
    Subprog {
        target_pc: usize,
        name: String,
        btf_id: Option<BtfTypeId>,
        r0: RegisterState,
        body: Vec<Expect>,
    },
}

/// Flattens an expected walk tree into the event stream it should produce,
/// wrapped in the root call framing every verification emits. `r0` is the
/// state the root walk exits with.
fn walk<const N: usize>(r0: RegisterState, body: [Expect; N]) -> Vec<RecordedEvent> {
    let mut events = vec![RecordedEvent::CallEnter {
        depth: 0,
        id: 0,
        target_pc: 0,
        name: String::new(),
        btf_id: None,
        registers: entry_registers(),
    }];
    let mut next_id = 1;
    flatten(body.into(), 0, &mut next_id, &mut events);
    events.push(RecordedEvent::CallExit { depth: 0, r0 });
    events
}

/// Walk ids are drawn from a counter as forks are created, matching the
/// verifier's [`Verifier::fork_at`]. A pruned arm is still a fork, so it draws
/// an id even though it never enters; a dead arm is not a fork and draws none.
fn flatten(body: Vec<Expect>, depth: usize, next_id: &mut usize, out: &mut Vec<RecordedEvent>) {
    for node in body {
        match node {
            Expect::Insn { pc, read, written } => out.push(RecordedEvent::Insn {
                depth,
                pc,
                read,
                written,
            }),
            Expect::Branch {
                target_pc,
                kind,
                body,
            } => {
                let id = *next_id;
                *next_id += 1;
                out.push(RecordedEvent::BranchEnter {
                    depth: depth + 1,
                    id,
                    target_pc,
                    kind,
                });
                flatten(body, depth + 1, next_id, out);
                out.push(RecordedEvent::BranchExit { depth: depth + 1 });
            }
            Expect::Dead { target_pc, kind } => out.push(RecordedEvent::BranchDead {
                depth: depth + 1,
                target_pc,
                kind,
            }),
            Expect::StatePruned {
                fork_pc,
                matched,
                site,
            } => {
                // A pruned arm is still a fork, so it drew an id from the
                // counter before it was cut, even though it emits no enter.
                *next_id += 1;
                out.push(RecordedEvent::StatePruned {
                    depth: depth + 1,
                    fork_pc,
                    matched,
                    site,
                });
            }
            Expect::Subprog {
                target_pc,
                name,
                btf_id,
                r0,
                body,
            } => {
                let id = *next_id;
                *next_id += 1;
                out.push(RecordedEvent::CallEnter {
                    depth: depth + 1,
                    id,
                    target_pc,
                    name,
                    btf_id,
                    registers: entry_registers(),
                });
                flatten(body, depth + 1, next_id, out);
                out.push(RecordedEvent::CallExit {
                    depth: depth + 1,
                    r0,
                });
            }
        }
    }
}

macro_rules! reg_idx {
    (r0) => {
        0u8
    };
    (r1) => {
        1u8
    };
    (r2) => {
        2u8
    };
    (r3) => {
        3u8
    };
    (r4) => {
        4u8
    };
    (r5) => {
        5u8
    };
    (r6) => {
        6u8
    };
    (r7) => {
        7u8
    };
    (r8) => {
        8u8
    };
    (r9) => {
        9u8
    };
    (r10) => {
        10u8
    };
}

macro_rules! refined {
    () => {
        None
    };
    ($r:ident = $v:expr) => {
        Some((reg_idx!($r), $v))
    };
}

macro_rules! btf_id {
    () => {
        None
    };
    ($id:literal) => {
        Some(BtfTypeId($id))
    };
}

/// `insn!(pc, read rA rB, write rC = state, rD = state)`, both clauses
/// optional.
macro_rules! insn {
    ($pc:literal $(, read $($r:ident)+)? $(, write $($w:ident = $v:expr),+)?) => {
        Expect::Insn {
            pc: $pc,
            read: reads(&[$($(reg_idx!($r)),+)?]),
            written: vec![$($((reg_idx!($w), $v)),+)?],
        }
    };
}

/// `branch!(fork_pc, target_pc, refine rN = state, [body])` for a walked
/// branch arm, with `refine` optional. `fork_pc` is the jump that spawned it.
/// Use [`fallthrough!`] for the fall-through arm, [`dead!`] for a ruled-out
/// arm, and [`pruned!`] when a walk stops on an already-visited state.
macro_rules! branch {
    ($base:literal, $target:literal $(, refine $r:ident = $v:expr)?, [$($body:expr),* $(,)?]) => {
        Expect::Branch {
            target_pc: $target,
            kind: WalkOrigin::Branch { refined: refined!($($r = $v)?), fork_pc: $base },
            body: vec![$($body),*],
        }
    };
}

/// `fallthrough!(fork_pc, target_pc, refine rN = state, [body])`, the
/// fall-through counterpart to [`branch!`].
macro_rules! fallthrough {
    ($base:literal, $target:literal $(, refine $r:ident = $v:expr)?, [$($body:expr),* $(,)?]) => {
        Expect::Branch {
            target_pc: $target,
            kind: WalkOrigin::Fallthrough { refined: refined!($($r = $v)?), fork_pc: $base },
            body: vec![$($body),*],
        }
    };
}

/// `dead!(fork_pc, target_pc, branch|fallthrough [refine rN = state])` for an
/// arm the comparison ruled out. `fork_pc` is shared with its live siblings.
macro_rules! dead {
    ($base:literal, $target:literal, branch $(, refine $r:ident = $v:expr)?) => {
        Expect::Dead {
            target_pc: $target,
            kind: WalkOrigin::Branch { refined: refined!($($r = $v)?), fork_pc: $base },
        }
    };
    ($base:literal, $target:literal, fallthrough $(, refine $r:ident = $v:expr)?) => {
        Expect::Dead {
            target_pc: $target,
            kind: WalkOrigin::Fallthrough { refined: refined!($($r = $v)?), fork_pc: $base },
        }
    };
}

/// `pruned!(fork_pc, matched, jump|arm)` for a walk that stops because walker
/// `matched` already covered its state at `fork_pc`. `jump` means `matched`
/// branched there, `arm` means `matched` entered there.
macro_rules! pruned {
    ($base:literal, $matched:literal, jump) => {
        Expect::StatePruned {
            fork_pc: $base,
            matched: $matched,
            site: PruneSite::Jump,
        }
    };
    ($base:literal, $matched:literal, arm) => {
        Expect::StatePruned {
            fork_pc: $base,
            matched: $matched,
            site: PruneSite::Arm,
        }
    };
}

/// `subprog!(target_pc, "name", btf id, ret state, [body])` with `btf`
/// optional and `ret` the state the call exits with.
macro_rules! subprog {
    ($target:literal, $name:literal $(, btf $btf:literal)?, ret $r0:expr, [$($body:expr),* $(,)?]) => {
        Expect::Subprog {
            target_pc: $target,
            name: $name.to_owned(),
            btf_id: btf_id!($($btf)?),
            r0: $r0,
            body: vec![$($body),*],
        }
    };
}

fn signature(name: &str, btf_id: Option<BtfTypeId>) -> FunctionSignature {
    FunctionSignature {
        name: name.to_owned(),
        btf_id,
        is_global: false,
        params_types: Vec::new(),
        return_type: None,
        section_idx: SectionIndex(0),
        section_offset: 0,
        size: 0,
    }
}

fn verify(
    insns: Vec<Insn>,
) -> (
    Result<VerificationOutput, VerifierError>,
    Vec<RecordedEvent>,
) {
    verify_with_subprogs(insns, BTreeMap::new())
}

fn verify_with_subprogs(
    insns: Vec<Insn>,
    subprogs: BTreeMap<usize, FunctionSignature>,
) -> (
    Result<VerificationOutput, VerifierError>,
    Vec<RecordedEvent>,
) {
    verify_in(&Vm::new(), insns, subprogs)
}

fn verify_in(
    vm: &Vm,
    insns: Vec<Insn>,
    subprogs: BTreeMap<usize, FunctionSignature>,
) -> (
    Result<VerificationOutput, VerifierError>,
    Vec<RecordedEvent>,
) {
    let prog = EbpfProgram {
        insns,
        func: signature("test_prog", None),
        maps: Vec::new(),
        btf: Arc::new(Btf::default()),
        hook: None,
        deferred: BTreeMap::new(),
        line_info: BTreeMap::new(),
        subprogs,
    };
    let log = Arc::new(EventLog::default());
    let config = VerifierConfig {
        capture: Some(log.clone()),
        ..Default::default()
    };
    let result = Verifier::new(vm, Arc::new(prog), &config)
        .expect("verifier construction must succeed")
        .run();
    let events = std::mem::take(&mut *log.0.lock().expect("event log lock poisoned"));
    (result, events)
}

fn encode(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Insn {
    Insn(
        u64::from(opcode)
            | u64::from(dst) << 8
            | u64::from(src) << 12
            | u64::from(offset as u16) << 16
            | u64::from(imm as u32) << 32,
    )
}

fn mov64_imm(dst: u8, imm: i32) -> Insn {
    encode(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
}

fn mov64_reg(dst: u8, src: u8) -> Insn {
    encode(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
}

fn alu32_imm(op: u8, dst: u8, imm: i32) -> Insn {
    encode(BPF_ALU32 | op | BPF_K, dst, 0, 0, imm)
}

fn alu64_imm(op: u8, dst: u8, imm: i32) -> Insn {
    encode(BPF_ALU64 | op | BPF_K, dst, 0, 0, imm)
}

fn alu64_reg(op: u8, dst: u8, src: u8) -> Insn {
    encode(BPF_ALU64 | op | BPF_X, dst, src, 0, 0)
}

fn stx(size: u8, dst: u8, src: u8, offset: i16) -> Insn {
    encode(BPF_STX | MODE_MEM | size, dst, src, offset, 0)
}

fn ldx(size: u8, dst: u8, src: u8, offset: i16) -> Insn {
    encode(BPF_LDX | MODE_MEM | size, dst, src, offset, 0)
}

fn jeq_imm(dst: u8, imm: i32, offset: i16) -> Insn {
    encode(BPF_JMP | BPF_JEQ | BPF_K, dst, 0, offset, imm)
}

fn jne_imm(dst: u8, imm: i32, offset: i16) -> Insn {
    encode(BPF_JMP | BPF_JNE | BPF_K, dst, 0, offset, imm)
}

fn ja(offset: i16) -> Insn {
    encode(BPF_JMP | BPF_JA, 0, 0, offset, 0)
}

fn call(imm: i32) -> Insn {
    encode(BPF_JMP | BPF_CALL | BPF_K, 0, BPF_PSEUDO_CALL, 0, imm)
}

fn helper_call(id: i32) -> Insn {
    encode(BPF_JMP | BPF_CALL | BPF_K, 0, BPF_HELPER_CALL, 0, id)
}

/// Two instruction words loading map `fd` into `dst`.
fn ld_map_fd(dst: u8, fd: i32) -> [Insn; 2] {
    [
        encode(0x18, dst, BPF_PSEUDO_MAP_FD, 0, fd),
        encode(0, 0, 0, 0, 0),
    ]
}

/// A VM holding one hash map at fd 0.
fn vm_with_hash_map(key_size: u32, value_size: u32) -> Arc<Vm> {
    let vm = Vm::new();
    let spec = MapSpec {
        name: "map".into(),
        r#type: Some(BPF_MAP_TYPE_HASH),
        key_size: Some(key_size),
        value_size: Some(value_size),
        max_entries: Some(16),
        ..Default::default()
    };
    let btf = Arc::new(Btf::default());
    let repr = MapRepr::create_from_btf(&btf, &spec).expect("hash map spec must be valid");
    vm.maps
        .lock()
        .expect("map lock poisoned")
        .push(Arc::new(BpfMap {
            fd: 0,
            repr,
            spec,
            btf,
        }));
    vm
}

fn exit() -> Insn {
    encode(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
}

fn exact(val: u64) -> RegisterState {
    RegisterState::Scalar(Scalar::U64(ScalarRange::exact(val)))
}

fn unknown() -> RegisterState {
    RegisterState::Scalar(Scalar::Unknown)
}

fn scalar64(min: u64, max: u64, stride: u64) -> RegisterState {
    RegisterState::Scalar(Scalar::U64(ScalarRange { min, max, stride }))
}

fn full64() -> RegisterState {
    scalar64(0, u64::MAX, 1)
}

fn stack_at(offset: u32) -> RegisterState {
    RegisterState::PtrToStack {
        offset: ScalarRange::exact(offset),
    }
}

fn reads(indices: &[u8]) -> RegMask {
    indices
        .iter()
        .fold(RegMask::empty(), |mask, &idx| mask | RegMask::single(idx))
}

fn entry_registers() -> Vec<RegisterState> {
    let mut registers = vec![RegisterState::Uninit; 10];
    registers.push(RegisterState::PtrToStack {
        offset: ScalarRange::exact(512),
    });
    registers
}

#[test]
fn straight_line_insns_report_written_state() {
    let (result, events) = verify(vec![mov64_imm(0, 7), mov64_reg(1, 0), exit()]);

    assert_eq!(result.expect("must verify").r0, exact(7));
    assert_eq!(
        events,
        walk(
            exact(7),
            [
                insn!(0, write r0 = exact(7)),
                insn!(1, read r0, write r1 = exact(7)),
                insn!(2, read r0),
            ]
        )
    );
}

#[test]
fn alu32_widens_dst_to_unknown() {
    let (result, events) = verify(vec![
        mov64_imm(0, 0),
        mov64_imm(1, 1),
        alu32_imm(BPF_ADD, 1, 1),
        exit(),
    ]);

    assert_eq!(result.expect("must verify").r0, exact(0));
    assert_eq!(
        events,
        walk(
            exact(0),
            [
                insn!(0, write r0 = exact(0)),
                insn!(1, write r1 = exact(1)),
                insn!(2, read r1, write r1 = unknown()),
                insn!(3, read r0),
            ]
        )
    );
}

#[test]
fn unknown_compare_walks_both_arms() {
    let (result, events) = verify(vec![
        mov64_imm(1, 0),
        alu32_imm(BPF_ADD, 1, 1),
        jeq_imm(1, 5, 2),
        mov64_imm(0, 0),
        exit(),
        mov64_imm(0, 1),
        exit(),
    ]);

    assert_eq!(result.expect("must verify").r0, exact(0));
    assert_eq!(
        events,
        walk(
            exact(0),
            [
                insn!(0, write r1 = exact(0)),
                insn!(1, read r1, write r1 = unknown()),
                insn!(2, read r1),
                branch!(2, 5, refine r1 = exact(5), [
                    insn!(5, write r0 = exact(1)),
                    insn!(6, read r0),
                ]),
                fallthrough!(2, 3, refine r1 = full64(), [
                    insn!(3, write r0 = exact(0)),
                    insn!(4, read r0),
                ]),
            ]
        )
    );
}

#[test]
fn known_true_compare_skips_fallthrough() {
    let (result, events) = verify(vec![
        mov64_imm(0, 0),
        mov64_imm(1, 5),
        jeq_imm(1, 5, 1),
        exit(),
        exit(),
    ]);

    assert_eq!(result.expect("must verify").r0, exact(0));
    assert_eq!(
        events,
        walk(
            exact(0),
            [
                insn!(0, write r0 = exact(0)),
                insn!(1, write r1 = exact(5)),
                insn!(2, read r1),
                branch!(2, 4, [insn!(4, read r0)]),
                dead!(2, 3, fallthrough),
            ]
        )
    );
}

#[test]
fn known_false_compare_skips_branch() {
    let (result, events) = verify(vec![
        mov64_imm(0, 0),
        mov64_imm(1, 4),
        jeq_imm(1, 5, 1),
        exit(),
        exit(),
    ]);

    assert_eq!(result.expect("must verify").r0, exact(0));
    assert_eq!(
        events,
        walk(
            exact(0),
            [
                insn!(0, write r0 = exact(0)),
                insn!(1, write r1 = exact(4)),
                insn!(2, read r1),
                dead!(2, 4, branch),
                fallthrough!(2, 3, [insn!(3, read r0)]),
            ]
        )
    );
}

#[test]
fn unconditional_jump_forks_with_skip_fallthrough() {
    let (result, events) = verify(vec![mov64_imm(0, 0), ja(1), exit(), exit()]);

    assert_eq!(result.expect("must verify").r0, exact(0));
    assert_eq!(
        events,
        walk(
            exact(0),
            [
                insn!(0, write r0 = exact(0)),
                insn!(1),
                branch!(1, 3, [insn!(3, read r0)]),
                dead!(1, 2, fallthrough),
            ]
        )
    );
}

// Two conditional jumps target the same exit, so the second reaches an arm's
// own entry snapshot rather than a shared branch jump. The first jump's arm
// (id 1) records the state at pc4, the second is pruned against it with
// `site=Arm` and `matched=1`, meaning `matched` is that arm directly and
// `fork_pc` (4) is its target, not a jump the arms hang off.
#[test]
fn state_pruned_matches_an_arm_on_a_shared_jump_target() {
    let (result, events) = verify(vec![
        helper_call(7),   // pc0: r0 = prandom (unknown)
        jne_imm(0, 0, 2), // pc1: if r0 != 0 goto pc4
        helper_call(7),   // pc2: r0 = prandom (unknown)
        jne_imm(0, 0, 0), // pc3: if r0 != 0 goto pc4
        exit(),           // pc4
    ]);

    assert_eq!(result.expect("must verify").r0, exact(0));
    assert_eq!(
        events,
        walk(
            exact(0),
            [
                insn!(0, write r0 = unknown()),
                insn!(1, read r0),
                branch!(1, 4, refine r0 = scalar64(1, u64::MAX, 1), [
                    insn!(4, read r0),
                ]),
                fallthrough!(1, 2, refine r0 = exact(0), [
                    insn!(2, write r0 = unknown()),
                    insn!(3, read r0),
                    pruned!(4, 1, arm),
                    fallthrough!(3, 4, refine r0 = exact(0), [
                        insn!(4, read r0),
                    ]),
                ]),
            ]
        )
    );
}

#[test]
fn subprogram_call_frames_with_name_and_btf_id() {
    let subprogs = BTreeMap::from([(2, signature("get_seven", Some(BtfTypeId(42))))]);
    let (result, events) =
        verify_with_subprogs(vec![call(1), exit(), mov64_imm(0, 7), exit()], subprogs);

    let output = result.expect("must verify");
    assert_eq!(output.r0, exact(7));
    assert_eq!(output.max_call_depth, 1);
    assert_eq!(
        events,
        walk(
            exact(7),
            [
                insn!(0),
                subprog!(2, "get_seven", btf 42, ret exact(7), [
                    insn!(2, write r0 = exact(7)),
                    insn!(3, read r0),
                ]),
                insn!(1, read r0),
            ]
        )
    );
}

#[test]
fn helper_call_reports_only_the_arguments_it_reads() {
    // bpf_probe_read_kernel (id 113) consults r1 through r3 only, so the
    // call's Insn event must not over-report r4 and r5 as read.
    let (result, events) = verify(vec![
        mov64_reg(1, 10),
        alu64_imm(BPF_ADD, 1, -8),
        mov64_imm(2, 8),
        mov64_imm(3, 0),
        helper_call(113),
        exit(),
    ]);

    assert_eq!(result.expect("must verify").r0, unknown());
    assert_eq!(
        events,
        walk(
            unknown(),
            [
                insn!(0, read r10, write r1 = stack_at(512)),
                insn!(1, read r1, write r1 = stack_at(504)),
                insn!(2, write r2 = exact(8)),
                insn!(3, write r3 = exact(0)),
                insn!(4, read r1 r2 r3, write r0 = unknown()),
                insn!(5, read r0),
            ]
        )
    );
}

#[test]
fn recursive_subprogram_call_fails() {
    let subprogs = BTreeMap::from([(0, signature("looper", None))]);
    let (result, _) = verify_with_subprogs(vec![call(-1), exit()], subprogs);

    let err = result.expect_err("recursion must fail verification");
    assert!(err.to_string().contains("recursive subprogram call"));
}

#[test]
fn call_chain_deeper_than_max_frames_fails() {
    let mut insns = Vec::new();
    let mut subprogs = BTreeMap::new();
    for link in 0..=MAX_CALL_FRAMES {
        insns.push(call(1));
        insns.push(exit());
        subprogs.insert((link + 1) * 2, signature("link", None));
    }
    insns.push(mov64_imm(0, 0));
    insns.push(exit());

    let (result, _) = verify_with_subprogs(insns, subprogs);
    let err = result.expect_err("call chain must exceed the frame limit");
    assert!(err.to_string().contains("call depth exceeds maximum"));
}

#[test]
fn scalar_alu_tracks_add_sub_shift() {
    let (result, events) = verify(vec![
        mov64_imm(0, 0),
        mov64_imm(1, 10),
        alu64_imm(BPF_ADD, 1, 5),
        alu64_imm(BPF_SUB, 1, 3),
        alu64_imm(BPF_LSH, 1, 2),
        exit(),
    ]);

    assert_eq!(result.expect("must verify").r0, exact(0));
    assert_eq!(
        events,
        walk(
            exact(0),
            [
                insn!(0, write r0 = exact(0)),
                insn!(1, write r1 = exact(10)),
                insn!(2, read r1, write r1 = exact(15)),
                insn!(3, read r1, write r1 = exact(12)),
                insn!(4, read r1, write r1 = scalar64(48, 48, 4)),
                insn!(5, read r0),
            ]
        )
    );
}

#[test]
fn untracked_scalar_ops_widen_to_unknown() {
    let (result, events) = verify(vec![
        mov64_imm(0, 0),
        mov64_imm(1, 6),
        mov64_imm(2, 2),
        alu64_imm(BPF_MUL, 1, 2),
        alu64_reg(BPF_ADD, 1, 2),
        exit(),
    ]);

    assert_eq!(result.expect("must verify").r0, exact(0));
    assert_eq!(
        events,
        walk(
            exact(0),
            [
                insn!(0, write r0 = exact(0)),
                insn!(1, write r1 = exact(6)),
                insn!(2, write r2 = exact(2)),
                insn!(3, read r1, write r1 = unknown()),
                insn!(4, read r1 r2, write r1 = unknown()),
                insn!(5, read r0),
            ]
        )
    );
}

#[test]
fn stack_pointer_arithmetic_tracks_offset() {
    let (result, events) = verify(vec![
        mov64_imm(0, 0),
        mov64_reg(1, 10),
        alu64_imm(BPF_ADD, 1, -16),
        mov64_imm(2, -8),
        alu64_reg(BPF_ADD, 2, 10),
        exit(),
    ]);

    assert_eq!(result.expect("must verify").r0, exact(0));
    assert_eq!(
        events,
        walk(
            exact(0),
            [
                insn!(0, write r0 = exact(0)),
                insn!(1, read r10, write r1 = stack_at(512)),
                insn!(2, read r1, write r1 = stack_at(496)),
                insn!(3, write r2 = exact(-8i64 as u64)),
                insn!(4, read r2 r10, write r2 = stack_at(504)),
                insn!(5, read r0),
            ]
        )
    );
}

#[test]
fn alu32_pointer_arithmetic_fails() {
    let (result, _) = verify(vec![mov64_reg(1, 10), alu32_imm(BPF_ADD, 1, 4), exit()]);

    let err = result.expect_err("ALU32 on a pointer must fail verification");
    assert!(
        err.to_string()
            .contains("ALU32 cannot perform pointer arithmetic")
    );
}

#[test]
fn stack_pointer_underflow_fails() {
    let (result, _) = verify(vec![mov64_reg(1, 10), alu64_imm(BPF_ADD, 1, -600), exit()]);

    let err = result.expect_err("stack underflow must fail verification");
    assert!(err.to_string().contains("new ptr overflows stack"));
}

#[test]
fn stack_slot_overlap() {
    let slot = |size: MemSize| StackSlot {
        size,
        state: unknown(),
        pc: 0,
    };

    use MemSize::{Dword, Half, Word};
    use StackSlotOverlap::{Disjoint, Exact, Partial};

    // an access of the same size at the same address
    assert_eq!(slot(Word).overlap(8, 8..12), Exact);

    // slots sitting entirely before or after the access
    assert_eq!(slot(Word).overlap(0, 8..12), Disjoint);
    assert_eq!(slot(Word).overlap(16, 8..12), Disjoint);
    assert_eq!(slot(Word).overlap(12, 8..12), Disjoint);

    // the access sits inside the slot, sharing its head, its tail, or neither
    assert_eq!(slot(Dword).overlap(8, 8..12), Partial(Bounds::Within));
    assert_eq!(slot(Dword).overlap(4, 8..12), Partial(Bounds::Within));
    assert_eq!(slot(Dword).overlap(6, 8..12), Partial(Bounds::Within));

    // the access runs off the slot's front, its back, and both at once
    assert_eq!(slot(Dword).overlap(10, 8..12), Partial(Bounds::Crossing));
    assert_eq!(slot(Dword).overlap(2, 8..12), Partial(Bounds::Crossing));
    assert_eq!(slot(Half).overlap(8, 8..16), Partial(Bounds::Crossing));
}

#[test]
fn partial_stack_read_of_a_scalar_is_unknown() {
    let (result, _) = verify(vec![
        mov64_imm(1, 0x1234),
        stx(SIZE_DW, 10, 1, -8),
        ldx(SIZE_W, 0, 10, -8),
        exit(),
    ]);

    result.expect("reading half of a scalar slot must verify");
}

#[test]
fn partial_stack_read_of_a_pointer_fails() {
    let (result, _) = verify(vec![
        stx(SIZE_DW, 10, 10, -8),
        ldx(SIZE_W, 0, 10, -8),
        exit(),
    ]);

    let err = result.expect_err("reading half of a pointer must fail verification");
    assert!(err.to_string().contains("would leak a pointer"));
}

#[test]
fn stack_read_crossing_a_slot_fails() {
    let (result, _) = verify(vec![
        mov64_imm(1, 1),
        stx(SIZE_W, 10, 1, -8),
        ldx(SIZE_DW, 0, 10, -8),
        exit(),
    ]);

    let err = result.expect_err("reading past a slot's end must fail verification");
    assert!(err.to_string().contains("crosses a slot boundary"));
}

#[test]
fn stack_read_spanning_two_slots_fails() {
    let (result, _) = verify(vec![
        mov64_imm(1, 1),
        stx(SIZE_W, 10, 1, -8),
        stx(SIZE_W, 10, 1, -4),
        ldx(SIZE_DW, 0, 10, -8),
        exit(),
    ]);

    let err = result.expect_err("reading across two slots must fail verification");
    assert!(err.to_string().contains("crosses a slot boundary"));
}

/// Looks up an 8 byte key whose pointer starts `key_offset` below r10, with
/// a 4 byte scalar stored there first.
fn lookup_with_key_at(key_offset: i16) -> Result<VerificationOutput, VerifierError> {
    let vm = vm_with_hash_map(8, 8);
    let mut insns = vec![
        mov64_imm(1, 3000),
        stx(SIZE_W, 10, 1, -key_offset),
        mov64_reg(2, 10),
        alu64_imm(BPF_ADD, 2, -key_offset as i32),
    ];
    insns.extend(ld_map_fd(1, 0));
    insns.extend([helper_call(1), exit()]);
    verify_in(&vm, insns, BTreeMap::new()).0
}

#[test]
fn map_key_running_past_the_stack_fails() {
    let err = lookup_with_key_at(4).expect_err("an 8 byte key at r10-4 must fail");
    assert!(
        err.to_string()
            .contains("helper memory runs past the stack")
    );
}

#[test]
fn map_key_within_the_stack_verifies() {
    lookup_with_key_at(8).expect("an 8 byte key at r10-8 must verify");
}

#[test]
fn map_key_holding_a_spilled_pointer_fails() {
    let vm = vm_with_hash_map(8, 8);
    let mut insns = vec![
        stx(SIZE_DW, 10, 10, -8),
        mov64_reg(2, 10),
        alu64_imm(BPF_ADD, 2, -8),
    ];
    insns.extend(ld_map_fd(1, 0));
    insns.extend([helper_call(1), exit()]);
    let (result, _) = verify_in(&vm, insns, BTreeMap::new());

    let err = result.expect_err("passing a spilled pointer as a key must fail");
    assert!(
        err.to_string()
            .contains("helper would read a spilled pointer")
    );
}

#[test]
fn helper_write_initializes_the_stack() {
    let (result, _) = verify(vec![
        mov64_reg(1, 10),
        alu64_imm(BPF_ADD, 1, -8),
        mov64_imm(2, 8),
        mov64_imm(3, 0),
        helper_call(113),
        ldx(SIZE_DW, 0, 10, -8),
        exit(),
    ]);

    assert_eq!(result.expect("must verify").r0, unknown());
}

#[test]
fn helper_write_past_the_stack_fails() {
    let (result, _) = verify(vec![
        mov64_reg(1, 10),
        alu64_imm(BPF_ADD, 1, -8),
        mov64_imm(2, 16),
        mov64_imm(3, 0),
        helper_call(113),
        exit(),
    ]);

    let err = result.expect_err("a 16 byte write at r10-8 must fail");
    assert!(
        err.to_string()
            .contains("helper memory runs past the stack")
    );
}

#[test]
fn unbounded_helper_size_fails() {
    let (result, _) = verify(vec![
        helper_call(7),
        mov64_reg(2, 0),
        mov64_reg(1, 10),
        alu64_imm(BPF_ADD, 1, -8),
        mov64_imm(3, 0),
        helper_call(113),
        exit(),
    ]);

    let err = result.expect_err("a size of unknown bound must fail");
    assert!(err.to_string().contains("must be a bounded scalar"));
}
