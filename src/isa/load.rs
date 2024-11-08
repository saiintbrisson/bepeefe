// For load and store instructions the 8-bit 'code' field is divided as:
//
//   +--------+--------+-------------------+
//   | 3 bits | 2 bits |   3 bits          |
//   |  mode  |  size  | instruction class |
//   +--------+--------+-------------------+
//   (MSB)                             (LSB)its
//
// From: <https://www.kernel.org/doc/Documentation/networking/filter.txt>

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
            pub fn $ld(state: &mut crate::State, val: u64, _: Option<u64>) {
                const SIZE: usize = ($size::BITS / 8) as usize;

                let dst = (val >> 8) & 0xF;
                let src = (val >> 12) & 0xF;
                let offset = (val >> 16) as i16;

                let ptr = (state.registers[src as usize] as isize + offset as isize) as usize;
                let val = state.stack[ptr - SIZE..ptr].try_into().unwrap();
                state.registers[dst as usize] = $size::from_ne_bytes(val) as u64;
            }

            pub fn $st(state: &mut crate::State, val: u64, _: Option<u64>) {
                const SIZE: usize = ($size::BITS / 8) as usize;

                let dst = (val >> 8) & 0xF;
                let src = (val >> 12) & 0xF;
                let offset = (val >> 16) as i16;

                let val = state.registers[src as usize] as $size;
                let ptr = (state.registers[dst as usize] as isize + offset as isize) as usize;
                (&mut state.stack[ptr - SIZE..ptr]).copy_from_slice(&val.to_ne_bytes());
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
