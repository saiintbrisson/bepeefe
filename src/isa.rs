//! Implementation of the BPF instruction set architecture.
//! This was based on the newly released ISA V4, RFC 9669.
//!
//! Reference: <https://datatracker.ietf.org/doc/rfc9669/>
#![allow(dead_code)]

/// non-standard load operations
pub const BPF_LD: u8 = 0x00;
/// load into register operations
pub const BPF_LDX: u8 = 0x01;
/// store from immediate operations
pub const BPF_ST: u8 = 0x02;
/// store from register operations
pub const BPF_STX: u8 = 0x03;
/// 32-bit arithmetic operations
pub const BPF_ALU: u8 = 0x04;
/// 64-bit jump operations
pub const BPF_JMP: u8 = 0x05;
/// 32-bit jump operations
pub const BPF_JMP32: u8 = 0x06;
/// 64-bit arithmetic operations
pub const BPF_ALU64: u8 = 0x07;

pub mod alu;
pub mod jmp;
pub mod load;

use alu::*;
use jmp::*;
use load::*;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Insn(pub u64);

impl Insn {
    pub const WIDTH: usize = size_of::<Self>();

    #[inline(always)]
    pub fn opcode(&self) -> u8 {
        (self.0 & 0xFF) as u8
    }
    #[inline(always)]
    pub fn dst_reg(&self) -> u8 {
        (self.0 >> 8) as u8 & 0xF
    }
    #[inline(always)]
    pub fn src_reg(&self) -> u8 {
        (self.0 >> 12) as u8 & 0xF
    }
    #[inline(always)]
    pub fn imm(&self) -> i32 {
        (self.0 >> 32) as i32
    }
    #[inline(always)]
    pub fn offset(&self) -> i16 {
        (self.0 >> 16) as i16
    }

    #[inline(always)]
    pub fn with_src_reg(&mut self, src_reg: u8) {
        self.0 = (self.0 & !(0xF << 12)) | ((src_reg as u64 & 0xF) << 12);
    }

    #[inline(always)]
    pub fn with_imm(&mut self, imm: i32) {
        self.0 = (self.0 << 32 >> 32) | ((imm as u64) << 32);
    }

    pub fn is_call(&self) -> bool {
        self.opcode() == BPF_JMP | BPF_CALL | BPF_K
    }

    pub fn is_subprog_call(&self) -> bool {
        self.is_call() && self.src_reg() == 1 && self.dst_reg() == 0 && self.offset() == 0
    }

    pub fn is_ld_imm64(&self) -> bool {
        self.opcode() == BPF_LD | MODE_IMM | SIZE_DW
    }
}

fn noop(_: &mut crate::vm::Vm, _: Insn) {}

macro_rules! instruction_table {
    ($($opcode:expr => $name:ident;)+) => {
        pub const INSTRUCTION_TABLE: [fn(&mut crate::vm::Vm, Insn); const {u8::MAX as usize + 1}] = {
            let mut table: [fn(&mut crate::vm::Vm, Insn); const {u8::MAX as usize + 1}] = [noop; const {u8::MAX as usize + 1}];
            $(table[$opcode as usize] = $name;)+
            table
        };

        pub const INSTRUCTION_NAME_TABLE: [&str; const {u8::MAX as usize + 1}] = {
            let mut table: [&str; const {u8::MAX as usize + 1}] = ["unknown";  const {u8::MAX as usize + 1}];
            $(table[$opcode as usize] = stringify!($name);)+
            table
        };
    };
}

instruction_table! {
    BPF_ALU   | BPF_X | BPF_ADD => add_src_32;
    BPF_ALU64 | BPF_X | BPF_ADD => add_src_64;
    BPF_ALU   | BPF_K | BPF_ADD => add_imm_32;
    BPF_ALU64 | BPF_K | BPF_ADD => add_imm_64;

    BPF_ALU   | BPF_X | BPF_SUB => sub_src_32;
    BPF_ALU64 | BPF_X | BPF_SUB => sub_src_64;
    BPF_ALU   | BPF_K | BPF_SUB => sub_imm_32;
    BPF_ALU64 | BPF_K | BPF_SUB => sub_imm_64;

    BPF_ALU   | BPF_X | BPF_MUL => mul_src_32;
    BPF_ALU64 | BPF_X | BPF_MUL => mul_src_64;
    BPF_ALU   | BPF_K | BPF_MUL => mul_imm_32;
    BPF_ALU64 | BPF_K | BPF_MUL => mul_imm_64;

    BPF_ALU   | BPF_X | BPF_DIV => div_src_32;
    BPF_ALU64 | BPF_X | BPF_DIV => div_src_64;
    BPF_ALU   | BPF_K | BPF_DIV => div_imm_32;
    BPF_ALU64 | BPF_K | BPF_DIV => div_imm_64;

    BPF_ALU   | BPF_X | BPF_OR => or_src_32;
    BPF_ALU64 | BPF_X | BPF_OR => or_src_64;
    BPF_ALU   | BPF_K | BPF_OR => or_imm_32;
    BPF_ALU64 | BPF_K | BPF_OR => or_imm_64;

    BPF_ALU   | BPF_X | BPF_AND => and_src_32;
    BPF_ALU64 | BPF_X | BPF_AND => and_src_64;
    BPF_ALU   | BPF_K | BPF_AND => and_imm_32;
    BPF_ALU64 | BPF_K | BPF_AND => and_imm_64;

    BPF_ALU   | BPF_X | BPF_LSH => lsh_src_32;
    BPF_ALU64 | BPF_X | BPF_LSH => lsh_src_64;
    BPF_ALU   | BPF_K | BPF_LSH => lsh_imm_32;
    BPF_ALU64 | BPF_K | BPF_LSH => lsh_imm_64;

    BPF_ALU   | BPF_X | BPF_RSH => rsh_src_32;
    BPF_ALU64 | BPF_X | BPF_RSH => rsh_src_64;
    BPF_ALU   | BPF_K | BPF_RSH => rsh_imm_32;
    BPF_ALU64 | BPF_K | BPF_RSH => rsh_imm_64;

    BPF_ALU   | BPF_K | BPF_NEG => neg_imm_32;
    BPF_ALU64 | BPF_K | BPF_NEG => neg_imm_64;

    BPF_ALU   | BPF_X | BPF_MOD => mod_src_32;
    BPF_ALU64 | BPF_X | BPF_MOD => mod_src_64;
    BPF_ALU   | BPF_K | BPF_MOD => mod_imm_32;
    BPF_ALU64 | BPF_K | BPF_MOD => mod_imm_64;

    BPF_ALU   | BPF_X | BPF_XOR => xor_src_32;
    BPF_ALU64 | BPF_X | BPF_XOR => xor_src_64;
    BPF_ALU   | BPF_K | BPF_XOR => xor_imm_32;
    BPF_ALU64 | BPF_K | BPF_XOR => xor_imm_64;

    BPF_ALU   | BPF_X | BPF_MOV => mov_src_32;
    BPF_ALU64 | BPF_X | BPF_MOV => mov_src_64;
    BPF_ALU   | BPF_K | BPF_MOV => mov_imm_32;
    BPF_ALU64 | BPF_K | BPF_MOV => mov_imm_64;

    BPF_ALU   | BPF_X | BPF_ARSH => arsh_src_32;
    BPF_ALU64 | BPF_X | BPF_ARSH => arsh_src_64;
    BPF_ALU   | BPF_K | BPF_ARSH => arsh_imm_32;
    BPF_ALU64 | BPF_K | BPF_ARSH => arsh_imm_64;

    BPF_ALU   | BPF_TO_LE | BPF_END => le;
    BPF_ALU   | BPF_TO_BE | BPF_END => be;
    BPF_ALU64 | BPF_END => swap;

    BPF_JMP32 | BPF_K | BPF_JA => ja_32;
    BPF_JMP   | BPF_K | BPF_JA => ja_64;

    BPF_JMP32 | BPF_X | BPF_JEQ => jeq_src_32;
    BPF_JMP32 | BPF_K | BPF_JEQ => jeq_imm_32;
    BPF_JMP   | BPF_X | BPF_JEQ => jeq_src_64;
    BPF_JMP   | BPF_K | BPF_JEQ => jeq_imm_64;

    BPF_JMP32 | BPF_X | BPF_JGT => jgt_src_32;
    BPF_JMP32 | BPF_K | BPF_JGT => jgt_imm_32;
    BPF_JMP   | BPF_X | BPF_JGT => jgt_src_64;
    BPF_JMP   | BPF_K | BPF_JGT => jgt_imm_64;

    BPF_JMP32 | BPF_X | BPF_JGE => jge_src_32;
    BPF_JMP32 | BPF_K | BPF_JGE => jge_imm_32;
    BPF_JMP   | BPF_X | BPF_JGE => jge_src_64;
    BPF_JMP   | BPF_K | BPF_JGE => jge_imm_64;

    BPF_JMP32 | BPF_X | BPF_JSET => jset_src_32;
    BPF_JMP32 | BPF_K | BPF_JSET => jset_imm_32;
    BPF_JMP   | BPF_X | BPF_JSET => jset_src_64;
    BPF_JMP   | BPF_K | BPF_JSET => jset_imm_64;

    BPF_JMP32 | BPF_X | BPF_JNE => jne_src_32;
    BPF_JMP32 | BPF_K | BPF_JNE => jne_imm_32;
    BPF_JMP   | BPF_X | BPF_JNE => jne_src_64;
    BPF_JMP   | BPF_K | BPF_JNE => jne_imm_64;

    BPF_JMP32 | BPF_X | BPF_JSGT => jsgt_src_32;
    BPF_JMP32 | BPF_K | BPF_JSGT => jsgt_imm_32;
    BPF_JMP   | BPF_X | BPF_JSGT => jsgt_src_64;
    BPF_JMP   | BPF_K | BPF_JSGT => jsgt_imm_64;

    BPF_JMP32 | BPF_X | BPF_JSGE => jsge_src_32;
    BPF_JMP32 | BPF_K | BPF_JSGE => jsge_imm_32;
    BPF_JMP   | BPF_X | BPF_JSGE => jsge_src_64;
    BPF_JMP   | BPF_K | BPF_JSGE => jsge_imm_64;

    BPF_JMP32 | BPF_X | BPF_JLT => jlt_src_32;
    BPF_JMP32 | BPF_K | BPF_JLT => jlt_imm_32;
    BPF_JMP   | BPF_X | BPF_JLT => jlt_src_64;
    BPF_JMP   | BPF_K | BPF_JLT => jlt_imm_64;

    BPF_JMP32 | BPF_X | BPF_JLE => jle_src_32;
    BPF_JMP32 | BPF_K | BPF_JLE => jle_imm_32;
    BPF_JMP   | BPF_X | BPF_JLE => jle_src_64;
    BPF_JMP   | BPF_K | BPF_JLE => jle_imm_64;

    BPF_JMP32 | BPF_X | BPF_JSLT => jslt_src_32;
    BPF_JMP32 | BPF_K | BPF_JSLT => jslt_imm_32;
    BPF_JMP   | BPF_X | BPF_JSLT => jslt_src_64;
    BPF_JMP   | BPF_K | BPF_JSLT => jslt_imm_64;

    BPF_JMP32 | BPF_X | BPF_JSLE => jsle_src_32;
    BPF_JMP32 | BPF_K | BPF_JSLE => jsle_imm_32;
    BPF_JMP   | BPF_X | BPF_JSLE => jsle_src_64;
    BPF_JMP   | BPF_K | BPF_JSLE => jsle_imm_64;

    BPF_JMP | BPF_K | BPF_CALL => jmp_call;
    BPF_JMP | BPF_K | BPF_EXIT => exit;

    BPF_LD | SIZE_DW | MODE_IMM => ld_imm64;

    BPF_LDX | SIZE_W | MODE_MEM => ldx_mem_w;
    BPF_STX | SIZE_W | MODE_MEM => stx_mem_w;

    BPF_LDX | SIZE_H | MODE_MEM => ldx_mem_h;
    BPF_STX | SIZE_H | MODE_MEM => stx_mem_h;

    BPF_LDX | SIZE_B | MODE_MEM => ldx_mem_b;
    BPF_STX | SIZE_B | MODE_MEM => stx_mem_b;

    BPF_LDX | SIZE_DW | MODE_MEM => ldx_mem_dw;
    BPF_STX | SIZE_DW | MODE_MEM => stx_mem_dw;

    BPF_STX | SIZE_DW | MODE_ATOMIC => stx_atomic_dw;
}
