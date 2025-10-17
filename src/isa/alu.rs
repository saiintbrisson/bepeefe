use super::Insn;

/// dst += src
pub const BPF_ADD: u8 = 0x00;
/// dst -= src
pub const BPF_SUB: u8 = 0x10;
/// dst *= src
pub const BPF_MUL: u8 = 0x20;
/// dst /= src
pub const BPF_DIV: u8 = 0x30;
/// dst |= src
pub const BPF_OR: u8 = 0x40;
/// dst &= src
pub const BPF_AND: u8 = 0x50;
/// dst <<= src
pub const BPF_LSH: u8 = 0x60;
/// dst >>= src
pub const BPF_RSH: u8 = 0x70;
/// dst = ~src
pub const BPF_NEG: u8 = 0x80;
/// dst %= src
pub const BPF_MOD: u8 = 0x90;
/// dst ^= src
pub const BPF_XOR: u8 = 0xa0;
/// dst = src
pub const BPF_MOV: u8 = 0xb0;
/// sign extending shift right
pub const BPF_ARSH: u8 = 0xc0;
/// byte swap operations (see Byte swap instructions below)
pub const BPF_END: u8 = 0xd0;

/// use 32-bit immediate as source operand
pub const BPF_K: u8 = 0x00;
/// use ‘src_reg’ register as source operand
pub const BPF_X: u8 = 0x08;

/// convert between host byte order and little endian
pub const BPF_TO_LE: u8 = 0x00;
/// convert between host byte order and big endian
pub const BPF_TO_BE: u8 = 0x08;

const SHIFT_MASK_32: u32 = 0x1F;
const SHIFT_MASK_64: u64 = 0x3F;

const BYTE_SWAP_ALLOWED_IMM: u64 = 16 | 32 | 64;

macro_rules! alu {
    ($($name:ident, |$dst:tt, $src:tt, $imm:tt| $func:expr;)+) => {
        $(
            #[inline(always)]
            pub fn $name(state: &mut crate::vm::Vm, insn: Insn) {
                let $src = state.registers[insn.src_reg() as usize];
                let $dst = state.registers[insn.dst_reg() as usize];
                let $imm = insn.imm() as u64;

                state.registers[insn.dst_reg() as usize] = $func as u64;
            }
        )+
    };
}

alu! {
    add_src_32,    |dst, src, _| (dst as u32).wrapping_add(src as u32);
    add_src_64,    |dst, src, _| dst.wrapping_add(src);
    add_imm_32,    |dst, _, imm| (dst as u32).wrapping_add(imm as u32);
    add_imm_64,    |dst, _, imm| dst.wrapping_add_signed(imm as i32 as i64);

    sub_src_32,    |dst, src, _| (dst as u32).wrapping_sub(src as u32);
    sub_src_64,    |dst, src, _| dst.wrapping_sub(src);
    sub_imm_32,    |dst, _, imm| (dst as u32).wrapping_sub(imm as u32);
    sub_imm_64,    |dst, _, imm| dst.wrapping_sub(imm);

    mul_src_32,    |dst, src, _| (dst as u32).wrapping_mul(src as u32);
    mul_src_64,    |dst, src, _| dst.wrapping_mul(src);
    mul_imm_32,    |dst, _, imm| (dst as u32).wrapping_mul(imm as u32);
    mul_imm_64,    |dst, _, imm| dst.wrapping_mul(imm);

    or_src_32,     |dst, src, _| dst as u32 | src as u32;
    or_src_64,     |dst, src, _| dst | src;
    or_imm_32,     |dst, _, imm| dst as u32 | imm as u32;
    or_imm_64,     |dst, _, imm| dst | imm;

    and_src_32,    |dst, src, _| dst as u32 & src as u32;
    and_src_64,    |dst, src, _| dst & src;
    and_imm_32,    |dst, _, imm| dst as u32 & imm as u32;
    and_imm_64,    |dst, _, imm| dst & imm;

    lsh_src_32,    |dst, src, _| (dst as u32) << (src as u32 & SHIFT_MASK_32);
    lsh_src_64,    |dst, src, _| dst << (src & SHIFT_MASK_64);
    lsh_imm_32,    |dst, _, imm| (dst as u32) << (imm as u32 & SHIFT_MASK_32);
    lsh_imm_64,    |dst, _, imm| dst << (imm & SHIFT_MASK_64);

    rsh_src_32,    |dst, src, _| dst as u32 >> (src as u32 & SHIFT_MASK_32);
    rsh_src_64,    |dst, src, _| dst >> (src & SHIFT_MASK_64);
    rsh_imm_32,    |dst, _, imm| dst as u32 >> (imm as u32 & SHIFT_MASK_32);
    rsh_imm_64,    |dst, _, imm| dst >> (imm as u64 & SHIFT_MASK_64);

    neg_imm_32,    |dst, _, _|   !dst as u32;
    neg_imm_64,    |dst, _, _|   !dst as u64;

    xor_src_32,    |dst, src, _| dst as u32 ^ src as u32;
    xor_src_64,    |dst, src, _| dst ^ src;
    xor_imm_32,    |dst, _, imm| dst as u32 ^ imm as u32;
    xor_imm_64,    |dst, _, imm| dst ^ imm;

    arsh_src_32,   |dst, src, _| dst as i32 >> (src as u32 & SHIFT_MASK_32);
    arsh_src_64,   |dst, src, _| dst as i64 >> (src & SHIFT_MASK_64);
    arsh_imm_32,   |dst, _, imm| dst as i32 >> (imm as u32 & SHIFT_MASK_32);
    arsh_imm_64,   |dst, _, imm| dst as i64 >> (imm & SHIFT_MASK_64);

    mov_imm_32,    |_, _, imm|   imm as u32;
    mov_imm_64,    |_, _, imm|   imm as u64;

    le,            |dst, _, imm| (dst & !(u64::MAX << (imm & BYTE_SWAP_ALLOWED_IMM))).to_le();
    be,            |dst, _, imm| (dst & !(u64::MAX << (imm & BYTE_SWAP_ALLOWED_IMM))).to_be();
    swap,          |dst, _, imm| (dst & !(u64::MAX << (imm & BYTE_SWAP_ALLOWED_IMM))).swap_bytes();
}

macro_rules! signed_alu {
    ($($name:ident { $($offset:pat => |$dst:tt, $src:tt, $imm:tt| $func:expr;)+ })+) => {
        $(
            #[inline(always)]
            pub fn $name(state: &mut crate::vm::Vm, insn: Insn) {
                let offset = insn.offset() & 1;
                state.registers[insn.dst_reg() as usize] = match offset {
                    $($offset => {
                        let $src = state.registers[insn.src_reg() as usize];
                        let $dst = state.registers[insn.dst_reg() as usize];
                        let $imm = insn.imm() as u64;
                        $func as u64
                    })+
                    _ => unreachable!(),
                }
            }
        )+
    };
}

signed_alu! {
    div_src_32 {
        0 | 1 => |dst, src, _| (dst as u32).checked_div(src as u32).unwrap_or_default();
    }
    div_src_64 {
        0 | 1 => |dst, src, _| dst.checked_div(src).unwrap_or_default();
    }
    div_imm_32 {
        0 => |dst, _, imm| (dst as u32).checked_div(imm as u32).unwrap_or_default();
        1 => |dst, _, imm| (dst as i32).checked_div(imm as i32).unwrap_or_default();
    }
    div_imm_64 {
        0 => |dst, _, imm| dst.checked_div(imm as i32 as u64).unwrap_or_default();
        1 => |dst, _, imm| (dst as i64).checked_div(imm as i32 as i64).unwrap_or_default();
    }

    mod_src_32 {
        0 | 1 => |dst, src, _| (dst as u32).checked_rem(src as u32).unwrap_or_default();
    }
    mod_src_64 {
        0 | 1 => |dst, src, _| dst.checked_rem(src).unwrap_or_default();
    }
    mod_imm_32 {
        0 => |dst, _, imm| (dst as u32).checked_rem(imm as u32).unwrap_or_default();
        1 => |dst, _, imm| (dst as i32).checked_rem(imm as i32).unwrap_or_default();
    }
    mod_imm_64 {
        0 => |dst, _, imm| dst.checked_rem(imm as i32 as u64).unwrap_or_default();
        1 => |dst, _, imm| (dst as i64).checked_rem(imm as i32 as i64).unwrap_or_default();
    }
}

macro_rules! mov_src {
    ($($name:ident, $uref:ty, $sref:ty, $mask:expr;)+) => {
        $(
            #[inline(always)]
            pub fn $name(state: &mut crate::vm::Vm, insn: Insn) {
                /// Offset can be either 0 for mov or 8/16/32 for movsx
                const MOVSX_OFFSET_MASK: u64 = $mask;

                let src = state.registers[insn.src_reg() as usize];
                let dst = &mut state.registers[insn.dst_reg() as usize];
                let offset = insn.offset() as u64 & MOVSX_OFFSET_MASK;

                // I could probably do the signed src cast in a way that this branch could be taken away
                if offset != 0 {
                    let shift = <$sref>::BITS as u64 - offset;
                    *dst = ((src as $sref) << shift >> shift) as $uref as u64;
                } else {
                    *dst = src as $uref as u64;
                }
            }
        )+
    };
}

mov_src! {
    mov_src_32, u32, i32, 8 | 16;
    mov_src_64, u64, i64, 8 | 16 | 32;
}
