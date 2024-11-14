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
            pub fn $name(state: &mut crate::vm::Vm, val: u64, _: Option<u64>) {
                let dst = (val >> 8) & 0xF;
                let src = (val >> 12) & 0xF;

                let $src = state.registers[src as usize];
                let $dst = state.registers[dst as usize];

                if $cond {
                    state.program_counter += (val >> 16) as i16 as i32;
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
            pub fn $name(state: &mut crate::vm::Vm, val: u64, _: Option<u64>) {
                let dst = (val >> 8) & 0xF;

                let $imm = (val >> 32);
                let $dst = state.registers[dst as usize];

                if $cond {
                    state.program_counter += (val >> 16) as i16 as i32;
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

pub fn ja_32(state: &mut crate::vm::Vm, val: u64, _: Option<u64>) {
    let imm = val >> 32;
    state.program_counter += imm as i32;
}

pub fn ja_64(state: &mut crate::vm::Vm, val: u64, _: Option<u64>) {
    let offset = (val >> 16) as i16;
    state.program_counter += offset as i32;
}

pub fn exit(state: &mut crate::vm::Vm, _: u64, _: Option<u64>) {
    state.pop_stack_frame();
}

pub fn jmp_call(state: &mut crate::vm::Vm, val: u64, _: Option<u64>) {
    let src = (val >> 12) & 0xF;
    let imm = val >> 32;

    match src {
        0 => {
            // These values are based on kernel version 6.8, but are subject to change. The
            // correct way to do this is with BTF and CO-RE support.
            match imm {
                // static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *)
                // 1;
                // R1: map pointer, R2: key pointer
                // R0: pointer to value
                1 => {
                    let map_idx = state.registers[1] as u32 as usize;
                    let key = GuestAddr(state.registers[2] as u32 as usize);
                    let elem = state.map_lookup_elem(map_idx, key);
                    state.registers[0] = elem.0 as u64;
                }
                // static long (* const bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) =
                // (void *) 6;
                // R1: addr, R2: size, R3/R4/R5: formatting stufffff
                // R0: n of written bytes or negative error code
                6 => {
                    let addr = state.registers[1] as u32 as usize;
                    let len = state.registers[2] as u32 as usize;

                    let data = state
                        .mem
                        .read(GuestAddr(addr), len)
                        .expect("addr is invalid");
                    let s = std::ffi::CStr::from_bytes_until_nul(&data);
                    eprintln!("Print: {s:?}");
                    state.registers[0] = s
                        .map(|f| f.to_bytes().len() as u64)
                        .unwrap_or(-22i64 as u64 /* EINVAL */);
                }
                // static __u64 (* const bpf_get_current_pid_tgid)(void) = (void *) 14;
                // R0: tgid << 32 | pid
                14 => {
                    // TODO: should the vm have a configurable execution context?
                    state.registers[0] = (0xDEAD << 32) | 0xBEEF;
                }
                call => {
                    panic!("unhandled {call}");
                }
            }
        }
        // BPF-local functions
        1 => state.call(imm as i32),
        // 2 => {}
        _ => {
            dbg!(src);
            todo!()
        }
    }
}
