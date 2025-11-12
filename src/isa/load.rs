//! For load and store instructions the 8-bit 'code' field is divided as:
//!
//!   +--------+--------+-------------------+
//!   | 3 bits | 2 bits |   3 bits          |
//!   |  mode  |  size  | instruction class |
//!   +--------+--------+-------------------+
//!   (MSB)                             (LSB)
//!
//! From: <https://github.com/torvalds/linux/blob/master/Documentation/bpf/classic_vs_extended.rst>
//!
//! The RFC itself doesn't specify the width of each section. Go figure.
//! This is the only possible arrangement, though, but I'd expect the RFC to
//! mention bit width of stuff...
#![allow(dead_code)]

use crate::{isa::Insn, vm::mem::GuestAddr};

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
            pub fn $ld(state: &mut crate::vm::Vm, insn: Insn) {
                const SIZE: usize = ($size::BITS / 8) as usize;

                let src = insn.src_reg() as usize;
                let dst = insn.dst_reg() as usize;
                let offset = insn.offset();

                let ptr = (state.registers[src as usize] as isize + offset as isize) as usize;
                let val = state.mem.read(
                    crate::vm::mem::GuestAddr(ptr),
                    SIZE
                ).unwrap().try_into().unwrap();

                state.registers[dst as usize] = $size::from_ne_bytes(val) as u64;
            }

            pub fn $st(state: &mut crate::vm::Vm, insn: Insn) {
                let src = insn.src_reg() as usize;
                let dst = insn.dst_reg() as usize;
                let offset = insn.offset();

                let val = state.registers[src as usize] as $size;
                let ptr = (state.registers[dst as usize] as isize + offset as isize) as usize;

                state.mem.write(
                    crate::vm::mem::GuestAddr(ptr),
                    &val.to_ne_bytes()
                ).expect("failed to write");
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
/// > of two consecutive 'struct bpf_insn' 8-byte blocks and interpreted as single
/// > instruction that loads 64-bit immediate value into a dst_reg.
/// > Classic BPF has similar instruction: BPF_LD | BPF_W | BPF_IMM which loads
/// > 32-bit immediate value into a register.
///
/// Ref: <https://www.kernel.org/doc/Documentation/networking/filter.txt>
/// Ref: <https://www.rfc-editor.org/rfc/rfc9669.html#name-64-bit-immediate-instructio>
/// Ref: <https://github.com/torvalds/linux/blob/7ea30958b3054f5e488fa0b33c352723f7ab3a2a/kernel/bpf/verifier.c#L20519>
/// Ref: <https://mechpen.github.io/posts/2019-08-03-bpf-map/>
pub fn ld_imm64(state: &mut crate::vm::Vm, insn: Insn) {
    let src = insn.src_reg() as usize;
    let dst = insn.dst_reg() as usize;
    let imm = insn.imm();

    let next_imm = (state.code.next().unwrap().imm() as u64) << 32;

    match src {
        0 => state.registers[dst] = next_imm | imm as u64,
        //
        1 => {
            assert!(state.map_by_fd_exists(insn.imm()));
            state.registers[dst] = imm as u64;
        }
        // 2 => dst = map_val(map_by_fd(imm)) + next_imm  imm: map fd      dst: data address
        // 3 => dst = var_addr(imm)                       imm: variable id dst: data address
        // 4 => dst = code_addr(imm)                      imm: integer     dst: code address
        // 5 => dst = map_by_idx(imm)                     imm: map index   dst: map
        // 6 => dst = map_val(map_by_idx(imm)) + next_imm imm: map index   dst: data address
        _ => unreachable!("unimplemented src reg for imm64 load: {src}"),
    }
}

// atomic add
pub const ATOMIC_ADD: u8 = 0x00;
// atomic or
pub const ATOMIC_OR: u8 = 0x40;
// atomic and
pub const ATOMIC_AND: u8 = 0x50;
// atomic xor
pub const ATOMIC_XOR: u8 = 0xa0;

/// modifier: return old value
pub const ATOMIC_FETCH: u8 = 0x01;
/// atomic exchange
pub const ATOMIC_XCHG: u8 = 0xE0 | ATOMIC_FETCH;
/// atomic compare and exchange
pub const ATOMIC_CMPXCHG: u8 = 0xF0;

pub fn stx_atomic_dw(state: &mut crate::vm::Vm, insn: Insn) {
    let src = insn.src_reg() as usize;
    let dst = insn.dst_reg() as usize;
    let imm = insn.imm();
    let offset = insn.offset();

    let ptr = (state.registers[dst as usize] as isize + offset as isize) as usize;

    match imm as u8 & 0xF0 {
        ATOMIC_ADD => {
            let val: u64 = state.mem.read_as(GuestAddr(ptr)).expect("failed to read");
            let new_val = val + state.registers[src as usize];
            state
                .mem
                .write(GuestAddr(ptr), &new_val.to_ne_bytes())
                .expect("failed to write");
            if imm as u8 & ATOMIC_FETCH != 0 {
                state.registers[src as usize] = val;
            }
        }
        ATOMIC_CMPXCHG if imm as u8 & ATOMIC_FETCH > 0 => {
            let expected = state.registers[0];
            let new_val = state.registers[src as usize];

            let old_val: u64 = state.mem.read_as(GuestAddr(ptr)).expect("failed to read");

            if expected == old_val {
                state
                    .mem
                    .write(GuestAddr(ptr), &new_val.to_ne_bytes())
                    .expect("failed to write");
            }

            state.registers[0] = old_val;
        }
        _ => todo!(),
    }
}
