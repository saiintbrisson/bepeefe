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

use crate::vm::mem::GuestAddr;

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
            pub fn $ld(state: &mut crate::vm::Vm, val: u64, _: Option<u64>) {
                const SIZE: usize = ($size::BITS / 8) as usize;

                let dst = (val >> 8) & 0xF;
                let src = (val >> 12) & 0xF;
                let offset = (val >> 16) as i16;

                let ptr = (state.registers[src as usize] as isize + offset as isize) as usize;
                let val = state.mem.read(
                    crate::vm::mem::GuestAddr(ptr),
                    SIZE
                ).unwrap().try_into().unwrap();

                state.registers[dst as usize] = $size::from_ne_bytes(val) as u64;
            }

            pub fn $st(state: &mut crate::vm::Vm, val: u64, _: Option<u64>) {
                let dst = (val >> 8) & 0xF;
                let src = (val >> 12) & 0xF;
                let offset = (val >> 16) as i16;

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

pub fn ld_imm64(state: &mut crate::vm::Vm, val: u64, next: Option<u64>) {
    let src = (val >> 12) as usize & 0xF;
    let dst = (val >> 8) as usize & 0xF;

    match src {
        0 => {
            state.program_counter += 1;
            let next_imm = next.unwrap();
            state.registers[dst] = next_imm | (val >> 32);
        }
        // 1 => dst = map_by_fd(imm)                      imm: map fd      dst: map
        // 2 => dst = map_val(map_by_fd(imm)) + next_imm  imm: map fd      dst: data address
        // 3 => dst = var_addr(imm)                       imm: variable id dst: data address
        // 4 => dst = code_addr(imm)                      imm: integer     dst: code address
        // 5 => dst = map_by_idx(imm)                     imm: map index   dst: map
        // 6 => dst = map_val(map_by_idx(imm)) + next_imm imm: map index   dst: data address
        _ => unreachable!("unimplemented src reg for imm64 load: {src}"),
    }
}

// atomic add
pub const ATOMIC_ADD: u64 = 0x00;
// atomic or
pub const ATOMIC_OR: u64 = 0x40;
// atomic and
pub const ATOMIC_AND: u64 = 0x50;
// atomic xor
pub const ATOMIC_XOR: u64 = 0xa0;

/// modifier: return old value
pub const ATOMIC_FETCH: u64 = 0x01;
/// atomic exchange
pub const ATOMIC_XCHG: u64 = 0xe0 | ATOMIC_FETCH;
/// atomic compare and exchange
pub const ATOMIC_CMPXCHG: u64 = 0xf0 | ATOMIC_FETCH;

pub fn stx_atomic_dw(state: &mut crate::vm::Vm, val: u64, _: Option<u64>) {
    let src = (val >> 12) as usize & 0xF;
    let dst = (val >> 8) as usize & 0xF;
    let offset = (val >> 16) as i16;
    let imm = val >> 32;

    match imm {
        ATOMIC_ADD | ATOMIC_FETCH => {
            let ptr = (state.registers[dst as usize] as isize + offset as isize) as usize;
            let val = state
                .mem
                .read(crate::vm::mem::GuestAddr(ptr), 8)
                .unwrap()
                .try_into()
                .unwrap();

            let val = u64::from_ne_bytes(val);
            let new_val = val + state.registers[src as usize];
            state
                .mem
                .write(GuestAddr(ptr), &new_val.to_ne_bytes())
                .expect("failed to write");
            state.registers[src as usize] = val;
        }
        _ => todo!(),
    }
}
