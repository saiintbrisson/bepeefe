//! For load and store instructions the 8-bit 'code' field is divided as:
//!
//!   +--------+--------+-------------------+
//!   | 3 bits | 2 bits |   3 bits          |
//!   |  mode  |  size  | instruction class |
//!   +--------+--------+-------------------+
//!   (MSB)                             (LSB)
//!
//! From: <https://github.com/torvalds/linux/blob/master/Documentation/bpf/classic_vs_extended.rst>
#![allow(dead_code)]

use crate::{isa::Insn, vm::ptr::TaggedPtr};

/// Store instructions MODE mask
pub const LOAD_MODE_MASK: u8 = 0b11100000;
/// Store instructions SIZE mask
pub const LOAD_SIZE_MASK: u8 = 0b11000;

/// 64-bit immediate instructions
pub const MODE_IMM: u8 = 0x0 << 5;
/// legacy BPF packet access (absolute)
pub const MODE_ABS: u8 = 0x1 << 5;
/// legacy BPF packet access (indirect)
pub const MODE_IND: u8 = 0x2 << 5;
/// regular load and store operations
pub const MODE_MEM: u8 = 0x3 << 5;
/// sign-extension load operations
pub const MODE_MEMSX: u8 = 0x4 << 5;
/// atomic operations (or xadd according to the kernel)
pub const MODE_ATOMIC: u8 = 0x6 << 5;

/// word (4 bytes)        
pub const SIZE_W: u8 = 0 << 3;
/// half word (2 bytes)   
pub const SIZE_H: u8 = 1 << 3;
/// byte                  
pub const SIZE_B: u8 = 2 << 3;
/// double word (8 bytes)
pub const SIZE_DW: u8 = 3 << 3;

macro_rules! mem_insns {
    ($($ld:ident, $st:ident, $size:ident;)+) => {
        $(
            pub fn $ld(state: &mut crate::vm::Cpu, insn: Insn) {
                const SIZE: usize = ($size::BITS / 8) as usize;

                let ptr = state.reg(insn.src_reg()).saturating_add_signed(insn.offset() as i64);
                let val: [_; SIZE] = state.read(ptr);

                state.set_reg(insn.dst_reg(), $size::from_ne_bytes(val) as u64);
            }

            pub fn $st(state: &mut crate::vm::Cpu, insn: Insn) {
                let ptr = state.reg(insn.dst_reg()).saturating_add_signed(insn.offset() as i64);
                let val = state.reg(insn.src_reg()) as $size;

                state.write(ptr, &val.to_ne_bytes());
            }
        )+
    };
}

mem_insns! {
    ldx_mem_w,   stx_mem_w,  u32;
    ldx_mem_h,   stx_mem_h,  u16;
    ldx_mem_b,   stx_mem_b,  u8;
    ldx_mem_dw,  stx_mem_dw, u64;
}

/// LD IMM64 will load the map address with the FD given in IMM.
pub const BPF_PSEUDO_MAP_FD: u8 = 1;
/// LD IMM64 will load map_val(map_by_fd(imm)) + next_imm.
pub const BPF_PSEUDO_MAP_VALUE: u8 = 2;

/// The non-conventional load with IMM mode uses the
/// wide instruction encoding to construct 64-bit
/// immediates. This is the only 16 byte instruction
/// in the ISA.
///
/// The src_reg field describes the operation, not all of
/// them use 64-bit immediates, though. It's important to
/// point out that the verifier replaces the custom
/// operations, like map_by_fd, by the actual map address
/// when loading the program. The same is done for var
/// accesses.
///
/// From the kernel documentation:
///
/// > eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM which consists
/// > of two consecutive 'struct bpf_insn' 8-byte blocks and interpreted as
/// > single
/// > instruction that loads 64-bit immediate value into a dst_reg.
/// > Classic BPF has similar instruction: BPF_LD | BPF_W | BPF_IMM which loads
/// > 32-bit immediate value into a register.
///
/// Ref: <https://www.kernel.org/doc/Documentation/networking/filter.txt>
/// Ref: <https://www.rfc-editor.org/rfc/rfc9669.html#name-64-bit-immediate-instructio>
/// Ref: <https://github.com/torvalds/linux/blob/7ea30958b3054f5e488fa0b33c352723f7ab3a2a/kernel/bpf/verifier.c#L20519>
/// Ref: <https://mechpen.github.io/posts/2019-08-03-bpf-map/>
pub fn ld_imm64(state: &mut crate::vm::Cpu, insn: Insn) {
    let dst = insn.dst_reg();
    let imm = insn.imm();

    let Some(next_insn) = state.insn_at(state.pc()) else {
        return;
    };

    let next_imm = (next_insn.imm() as u64) << 32;
    state.advance_pc();

    match insn.src_reg() {
        0 => state.set_reg(dst, next_imm | imm as u64),
        BPF_PSEUDO_MAP_FD => state.set_reg(dst, imm as u64),
        BPF_PSEUDO_MAP_VALUE => {
            let map = state.get_map(imm as u16);
            let Some(base) = map.repr.lookup(&0u32.to_ne_bytes()) else {
                return;
            };
            state.set_reg(
                dst,
                TaggedPtr::map(map.fd as u16, base as u32 + (next_imm >> 32) as u32),
            );
        }
        // 3 => dst = var_addr(imm)                       imm: variable id dst: data address
        // 4 => dst = code_addr(imm)                      imm: integer     dst: code address
        // 5 => dst = map_by_idx(imm)                     imm: map index   dst: map
        // 6 => dst = map_val(map_by_idx(imm)) + next_imm imm: map index   dst: data address
        _ => {}
    }
}

pub const ATOMIC_ADD: u8 = 0x00;
pub const ATOMIC_OR: u8 = 0x40;
pub const ATOMIC_AND: u8 = 0x50;
pub const ATOMIC_XOR: u8 = 0xa0;

/// Modifier: return old value
pub const ATOMIC_FETCH: u8 = 0x01;
/// Atomic exchange
pub const ATOMIC_XCHG: u8 = 0xE0 | ATOMIC_FETCH;
/// Atomic compare and exchange
pub const ATOMIC_CMPXCHG: u8 = 0xF0;

pub fn stx_atomic_dw(state: &mut crate::vm::Cpu, insn: Insn) {
    let src = insn.src_reg();
    let dst = insn.dst_reg();
    let imm = insn.imm();

    let ptr = state.reg(dst).saturating_add_signed(insn.offset() as i64);

    match imm as u8 & 0xF0 {
        ATOMIC_ADD => {
            let val = u64::from_ne_bytes(state.read(ptr));
            let new_val = val + state.reg(src);
            state.write(ptr, &new_val.to_ne_bytes());
            if imm as u8 & ATOMIC_FETCH != 0 {
                state.set_reg(src, val);
            }
        }
        ATOMIC_CMPXCHG if imm as u8 & ATOMIC_FETCH > 0 => {
            let expected = state.reg(0);
            let new_val = state.reg(src);
            let old_val = u64::from_ne_bytes(state.read(ptr));

            if expected == old_val {
                state.write(ptr, &new_val.to_ne_bytes());
            }

            state.set_reg(0, old_val);
        }
        _ => {}
    }
}
