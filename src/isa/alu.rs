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

macro_rules! alu {
    ($($name:ident, |$dst:tt, $src:tt, $imm:tt| $func:expr;)+) => {
        $(
            #[inline(always)]
            pub fn $name(state: &mut crate::State, val: u64, _: Option<u64>) {
                let dst = (val >> 8) & 0xF;
                let src = (val >> 12) & 0xF;

                let $src = state.registers[src as usize];
                let $dst = &mut state.registers[dst as usize];
                let $imm = (val >> 32) as u32;

                $func;
            }
        )+
    };
}

alu! {
    add_src_32,    |dst, src, _| *dst = ((*dst as u32) + (src as u32)) as u64;
    add_src_64,    |dst, src, _| *dst += src;
    add_imm_32,    |dst, _, imm| *dst = ((*dst as u32) + imm) as u64;
    add_imm_64,    |dst, _, imm| *dst += imm as u64;
    sub_src_32,    |dst, src, _| *dst = ((*dst as u32) - (src as u32)) as u64;
    sub_src_64,    |dst, src, _| *dst -= src;
    sub_imm_32,    |dst, _, imm| *dst = ((*dst as u32) - imm) as u64;
    sub_imm_64,    |dst, _, imm| *dst -= imm as u64;
    mul_src_32,    |dst, src, _| *dst = ((*dst as u32) * (src as u32)) as u64;
    mul_src_64,    |dst, src, _| *dst *= src;
    mul_imm_32,    |dst, _, imm| *dst = ((*dst as u32) * imm) as u64;
    mul_imm_64,    |dst, _, imm| *dst *= imm as u64;
    div_src_32,    |dst, src, _| *dst = ((*dst as u32) / (src as u32)) as u64;
    div_src_64,    |dst, src, _| *dst /= src;
    div_imm_32,    |dst, _, imm| *dst = ((*dst as u32) / imm) as u64;
    div_imm_64,    |dst, _, imm| *dst /= imm as u64;
    or_src_32,     |dst, src, _| *dst = ((*dst as u32) | (src as u32)) as u64;
    or_src_64,     |dst, src, _| *dst |= src;
    or_imm_32,     |dst, _, imm| *dst = ((*dst as u32) | imm) as u64;
    or_imm_64,     |dst, _, imm| *dst |= imm as u64;
    and_src_32,    |dst, src, _| *dst = ((*dst as u32) & (src as u32)) as u64;
    and_src_64,    |dst, src, _| *dst &= src;
    and_imm_32,    |dst, _, imm| *dst = ((*dst as u32) & imm) as u64;
    and_imm_64,    |dst, _, imm| *dst &= imm as u64;
    lsh_src_32,    |dst, src, _| *dst = ((*dst as u32) << (src as u32)) as u64;
    lsh_src_64,    |dst, src, _| *dst <<= src;
    lsh_imm_32,    |dst, _, imm| *dst = ((*dst as u32) << imm) as u64;
    lsh_imm_64,    |dst, _, imm| *dst <<= imm as u64;
    rsh_src_32,    |dst, src, _| *dst = ((*dst as u32) >> (src as u32)) as u64;
    rsh_src_64,    |dst, src, _| *dst >>= src;
    rsh_imm_32,    |dst, _, imm| *dst = ((*dst as u32) >> imm) as u64;
    rsh_imm_64,    |dst, _, imm| *dst >>= imm as u64;
    neg_src_32,    |dst, src, _| *dst = !(src as u32) as u64;
    neg_src_64,    |dst, src, _| *dst = !src;
    neg_imm_32_64, |dst, _, imm| *dst = !imm as u64;
    mod_src_32,    |dst, src, _| *dst = ((*dst as u32) % (src as u32)) as u64;
    mod_src_64,    |dst, src, _| *dst %= src;
    mod_imm_32,    |dst, _, imm| *dst = ((*dst as u32) % imm) as u64;
    mod_imm_64,    |dst, _, imm| *dst %= imm as u64;
    xor_src_32,    |dst, src, _| *dst = ((*dst as u32) ^ (src as u32)) as u64;
    xor_src_64,    |dst, src, _| *dst ^= src;
    xor_imm_32,    |dst, _, imm| *dst = ((*dst as u32) ^ imm) as u64;
    xor_imm_64,    |dst, _, imm| *dst ^= imm as u64;
    mov_src_32,    |dst, src, _| *dst = (src as u32) as u64;
    mov_src_64,    |dst, src, _| *dst = src;
    mov_imm_32_64, |dst, _, imm| *dst = imm as u64;
    arsh_src_32,   |dst, src, _| *dst = ((*dst as i32) >> (src as u32)) as u64;
    arsh_src_64,   |dst, src, _| *dst = ((*dst as i64) >> src) as u64;
    arsh_imm_32,   |dst, _, imm| *dst = ((*dst as i32) >> imm) as u64;
    arsh_imm_64,   |dst, _, imm| *dst = ((*dst as i64) >> imm) as u64;
    le,            |dst, _, imm| *dst = (*dst & !(u64::MAX << imm)).to_le() as u64;
    be,            |dst, _, imm| *dst = (*dst & !(u64::MAX << imm)).to_be() as u64;
}
