use std::ffi::CStr;

use super::Insn;
use crate::vm::mem::GuestAddr;

/// src = 0x0, PC += offset, BPF_JMP only
pub const BPF_JA: u8 = 0x00;
/// src = any, PC += offset if dst == src
pub const BPF_JEQ: u8 = 0x10;
/// src = any, PC += offset if dst > src, unsigned
pub const BPF_JGT: u8 = 0x20;
/// src = any, PC += offset if dst >= src, unsigned
pub const BPF_JGE: u8 = 0x30;
/// src = any, PC += offset if dst & src
pub const BPF_JSET: u8 = 0x40;
/// src = any, PC += offset if dst != src
pub const BPF_JNE: u8 = 0x50;
/// src = any, PC += offset if dst > src, signed
pub const BPF_JSGT: u8 = 0x60;
/// src = any, PC += offset if dst >= src, signed
pub const BPF_JSGE: u8 = 0x70;
/// src = 0x0, call platform-agnostic helper function imm, see Platform-agnostic
/// helper functions (Section 4.2.1) src = 0x1, call PC += offset, see BPF-local
/// functions (Section 4.2.3) src = 0x2, call platform-specific helper function
/// imm, see Platform-specific helper functions (Section 4.2.2)
pub const BPF_CALL: u8 = 0x80;
/// src = 0x0, return, BPF_JMP only
pub const BPF_EXIT: u8 = 0x90;
/// src = any, PC += offset if dst < src, unsigned
pub const BPF_JLT: u8 = 0xa0;
/// src = any, PC += offset if dst <= src, unsigned
pub const BPF_JLE: u8 = 0xb0;
/// src = any, PC += offset if dst < src, signed
pub const BPF_JSLT: u8 = 0xc0;
/// src = any, PC += offset if dst <= src, signed
pub const BPF_JSLE: u8 = 0xd0;

macro_rules! jmp_src_cond {
    ($($name:ident, |$dst:tt, $src:tt| $cond:expr;)+) => {
        $(
            #[inline(always)]
            pub fn $name(state: &mut crate::vm::Vm, insn: Insn) {
                let dst = insn.dst_reg();
                let src = insn.src_reg();

                let $src = state.registers[src as usize];
                let $dst = state.registers[dst as usize];

                if $cond {
                    state.code.add_offset(insn.offset() as isize);
                }
            }
        )+
    };
}

jmp_src_cond! {
    jeq_src_32,  |dst, src| (dst as u32) == (src as u32);
    jeq_src_64,  |dst, src| dst == src;
    jgt_src_32,  |dst, src| (dst as u32) > (src as u32);
    jgt_src_64,  |dst, src| dst > src;
    jge_src_32,  |dst, src| (dst as u32) >= (src as u32);
    jge_src_64,  |dst, src| dst >= src;
    jset_src_32, |dst, src| (dst as u32) & (src as u32) != 0;
    jset_src_64, |dst, src| dst & src != 0;
    jne_src_32,  |dst, src| (dst as u32) != (src as u32);
    jne_src_64,  |dst, src| dst != src;
    jsgt_src_32, |dst, src| (dst as i32) > (src as i32);
    jsgt_src_64, |dst, src| (dst as i64) > (src as i64);
    jsge_src_32, |dst, src| (dst as i32) >= (src as i32);
    jsge_src_64, |dst, src| (dst as i64) >= (src as i64);
    jlt_src_32,  |dst, src| (dst as u32) < (src as u32);
    jlt_src_64,  |dst, src| dst < src;
    jle_src_32,  |dst, src| (dst as u32) <= (src as u32);
    jle_src_64,  |dst, src| dst <= src;
    jslt_src_32, |dst, src| (dst as i32) < (src as i32);
    jslt_src_64, |dst, src| (dst as i64) < (src as i64);
    jsle_src_32, |dst, src| (dst as i32) <= (src as i32);
    jsle_src_64, |dst, src| (dst as i64) <= (src as i64);
}

macro_rules! jmp_imm_cond {
    ($($name:ident, |$dst:tt, $imm:tt| $cond:expr;)+) => {
        $(
            #[inline(always)]
            pub fn $name(state: &mut crate::vm::Vm, insn: Insn) {
                let dst = insn.dst_reg();

                let $imm = insn.imm() as u64;
                let $dst = state.registers[dst as usize];

                if $cond {
                    state.code.add_offset(insn.offset() as isize);
                }
            }
        )+
    };
}

jmp_imm_cond! {
    jeq_imm_32,  |dst, imm| (dst as u32) == (imm as u32);
    jeq_imm_64,  |dst, imm| dst == imm;
    jgt_imm_32,  |dst, imm| (dst as u32) > (imm as u32);
    jgt_imm_64,  |dst, imm| dst > imm;
    jge_imm_32,  |dst, imm| (dst as u32) >= (imm as u32);
    jge_imm_64,  |dst, imm| dst >= imm;
    jset_imm_32, |dst, imm| (dst as u32) & (imm as u32) != 0;
    jset_imm_64, |dst, imm| dst & imm != 0;
    jne_imm_32,  |dst, imm| (dst as u32) != (imm as u32);
    jne_imm_64,  |dst, imm| dst != imm;
    jsgt_imm_32, |dst, imm| (dst as i32) > (imm as i32);
    jsgt_imm_64, |dst, imm| (dst as i64) > (imm as i64);
    jsge_imm_32, |dst, imm| (dst as i32) >= (imm as i32);
    jsge_imm_64, |dst, imm| (dst as i64) >= (imm as i64);
    jlt_imm_32,  |dst, imm| (dst as u32) < (imm as u32);
    jlt_imm_64,  |dst, imm| dst < imm;
    jle_imm_32,  |dst, imm| (dst as u32) <= (imm as u32);
    jle_imm_64,  |dst, imm| dst <= imm;
    jslt_imm_32, |dst, imm| (dst as i32) < (imm as i32);
    jslt_imm_64, |dst, imm| (dst as i64) < (imm as i64);
    jsle_imm_32, |dst, imm| (dst as i32) <= (imm as i32);
    jsle_imm_64, |dst, imm| (dst as i64) <= (imm as i64);
}

pub fn ja_32(state: &mut crate::vm::Vm, insn: Insn) {
    state.code.add_offset(insn.imm() as isize);
}

pub fn ja_64(state: &mut crate::vm::Vm, insn: Insn) {
    state.code.add_offset(insn.offset() as isize);
}

pub fn exit(state: &mut crate::vm::Vm, _: Insn) {
    state.pop_stack_frame();
}

const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_FUNC_MAP_UPDATE_ELEM: i32 = 2;
const BPF_FUNC_TRACE_PRINTK: i32 = 6;
const BPF_FUNC_GET_CURRENT_PID_TGID: i32 = 14;

/// Performs a call jump.
///
/// The src_reg defines the type of jump. If 0, the
/// calls are platform-defined functions identified
/// by the immediate instruction value. Kernel functions
/// are defined in the `bpf_func_id` enum. If 1, imm is
/// used as PC-rel offset, and a stack frame is pushed.
///
/// Ref: <https://github.com/torvalds/linux/blob/98ac9cc4b4452ed7e714eddc8c90ac4ae5da1a09/include/uapi/linux/bpf.h#L5870>
pub fn jmp_call(state: &mut crate::vm::Vm, insn: Insn) {
    let src = insn.src_reg();

    match src {
        // BPF-local functions
        1 => state.call(insn.imm()),
        0 => {
            // The correct way to do this is with BTF and CO-RE support.
            match insn.imm() {
                // static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *)
                // 1;
                // R1: map pointer, R2: key pointer
                // R0: pointer to value
                BPF_FUNC_MAP_LOOKUP_ELEM => {
                    let map_idx = state.registers[1] as u32 as usize;
                    let key = GuestAddr(state.registers[2] as u32 as usize);
                    let elem = state.map_lookup_elem(map_idx, key);
                    state.registers[0] = elem.0 as u64;
                }
                // static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *)
                // 1;
                // R1: map pointer, R2: key pointer, R3: value, R4: flags
                // R0: success or errno
                BPF_FUNC_MAP_UPDATE_ELEM => {
                    let map_idx = state.registers[1] as u32 as usize;
                    let map = state.map_by_id(map_idx).unwrap();
                    let key_size = map.repr.key_size();
                    let value_size = map.repr.value_size();
                    let _ = map;

                    let key_addr = GuestAddr(state.registers[2] as u32 as usize);
                    let key = state
                        .mem
                        .read(key_addr, key_size)
                        .expect("tried reading of memory bounds")
                        .to_vec();
                    let value_addr = GuestAddr(state.registers[3] as u32 as usize);
                    let value_ptr = state.mem.into_ptr(value_addr, value_size).unwrap();

                    let map = state.map_by_id(map_idx).unwrap();
                    map.repr.update_elem(&key, value_ptr).unwrap();
                    state.registers[0] = 0;
                }
                // static long (* const bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) =
                // (void *) 6;
                // R1: addr, R2: size, R3/R4/R5: formatting params
                // R0: n of written bytes or negative error code
                BPF_FUNC_TRACE_PRINTK => {
                    let addr = state.registers[1] as u32 as usize;
                    let len = state.registers[2] as u32 as usize;

                    let data = state
                        .mem
                        .read(GuestAddr(addr), len)
                        .expect("addr is invalid");
                    let Ok(s) = CStr::from_bytes_until_nul(&data) else {
                        state.registers[0] = -22i64 as u64 /* EINVAL */;
                        return;
                    };
                    let Ok(s) = s.to_str() else {
                        panic!("string is not utf8");
                    };

                    let s = prepare_bpf_trace_printk(state, s.to_string());
                    state.registers[0] = s.as_bytes().len() as u64;
                    eprintln!("Print: {s:?}");
                }
                // static __u64 (* const bpf_get_current_pid_tgid)(void) = (void *) 14;
                // R0: tgid << 32 | pid
                BPF_FUNC_GET_CURRENT_PID_TGID => {
                    // TODO: should the vm have a configurable execution context?
                    state.registers[0] = (0xDEAD << 32) | 0xBEEF;
                }
                call => {
                    panic!("unhandled {call}");
                }
            }
        }
        2 => todo!(""),
        _ => {
            panic!()
        }
    }
}

/// Prepares the formatting string for `printk()` calls.
///
/// This is a very small reproduction of the Kernel's `printk`
/// functionality, currently only supporting two specifiers,
/// `d` and `s`.
///
/// From the kernel:
/// > The conversion specifiers supported by *fmt* are similar, but
/// > more limited than for printk(). They are **%d**, **%i**,
/// > **%u**, **%x**, **%ld**, **%li**, **%lu**, **%lx**, **%lld**,
/// > **%lli**, **%llu**, **%llx**, **%p**, **%s**. No modifier (size
/// > of field, padding with zeroes, etc.) is available, and the
/// > helper will return **-EINVAL** (but print nothing) if it
/// > encounters an unknown specifier.
///
/// Ref: <https://github.com/torvalds/linux/blob/f406055cb18c6e299c4a783fc1effeb16be41803/include/uapi/linux/bpf.h#L1961>
fn prepare_bpf_trace_printk(state: &mut crate::vm::Vm, s: String) -> String {
    let mut arg_count = 0;

    let mut buf: Option<Vec<_>> = None;
    let mut formatting = false;
    for (idx, c) in s.char_indices() {
        if formatting {
            arg_count += 1;
            if arg_count >= 4 {
                panic!()
            }

            let param = state.registers[2 + arg_count];
            let buf = buf.as_mut().unwrap();
            match c {
                'd' => {
                    buf.extend(param.to_string().as_bytes());
                }
                's' => {
                    let addr = GuestAddr(param as _);
                    let s = state.mem.read_str(addr).unwrap();
                    buf.extend(s.to_bytes());
                }
                _ => todo!(),
            }
            formatting = false;
        } else if c == '%' {
            if buf.is_none() {
                let mut items = Vec::with_capacity(s.len());
                items.extend_from_slice(&s.as_bytes()[..idx]);
                buf = Some(items)
            }
            formatting = true;
        } else if let Some(buf) = &mut buf {
            buf.push(s.as_bytes()[idx]);
        }
    }

    if let Some(buf) = buf {
        let s = String::from_utf8(buf).unwrap();
        s
    } else {
        s
    }
}
