use super::Insn;
use crate::vm::helpers;

/// JMP instructions OP mask
pub const JMP_OP_MASK: u8 = 0b11110000;

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
            pub fn $name(state: &mut crate::vm::Cpu, insn: Insn) {
                let $src = state.reg(insn.src_reg());
                let $dst = state.reg(insn.dst_reg());

                if $cond {
                    state.advance_pc_by(insn.offset() as isize);
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
            pub fn $name(state: &mut crate::vm::Cpu, insn: Insn) {
                let $imm = insn.imm() as u64;
                let $dst = state.reg(insn.dst_reg());

                if $cond {
                    state.advance_pc_by(insn.offset() as isize);
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

pub fn ja_32(state: &mut crate::vm::Cpu, insn: Insn) {
    state.advance_pc_by(insn.imm() as isize);
}

pub fn ja_16(state: &mut crate::vm::Cpu, insn: Insn) {
    state.advance_pc_by(insn.offset() as isize);
}

pub fn exit(state: &mut crate::vm::Cpu, _: Insn) {
    state.call_exit();
}

/// Ref: <https://github.com/libbpf/libbpf/blob/d65dbb412d661acae9d67c3786be5b36005b2ac1/include/uapi/linux/bpf.h#L1357-L1364>
pub const BPF_PSEUDO_CALL: u8 = 1;
pub const BPF_PSEUDO_KFUNC_CALL: u8 = 2;
pub const BPF_HELPER_CALL: u8 = 0;

/// Performs a call jump.
///
/// The src_reg defines the type of jump. If 0, the
/// calls are platform-defined functions identified
/// by the immediate instruction value. Kernel functions
/// are defined in the `bpf_func_id` enum. If 1, imm is
/// used as PC-rel offset, and a stack frame is pushed.
///
/// Ref: <https://github.com/torvalds/linux/blob/98ac9cc4b4452ed7e714eddc8c90ac4ae5da1a09/include/uapi/linux/bpf.h#L5870>
pub fn jmp_call(state: &mut crate::vm::Cpu, insn: Insn) {
    let src = insn.src_reg();

    match src {
        // BPF-local functions / subprograms
        BPF_PSEUDO_CALL => state.call(insn.imm()),
        BPF_HELPER_CALL => {
            if let Some(helper) = helpers::lookup(insn.imm()) {
                helper.exec(state, insn)
            }
        }
        #[expect(
            clippy::todo,
            reason = "kfunc support is a deliberate missing feature; programs reaching here failed \
                      to be rejected by the verifier (which does not yet handle kfunc src_reg)"
        )]
        BPF_PSEUDO_KFUNC_CALL => todo!("kfunc calls not implemented"),
        _ => {}
    }
}
