//! Implementation of the BPF instruction set architecture.
//! This was based on the newley released ISA V4, RFC 9669.
//!
//! Reference: <https://datatracker.ietf.org/doc/rfc9669/>

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

mod alu;
mod jmp;
mod load;

use alu::*;
use jmp::*;
use load::*;

fn noop(_: &mut crate::State, _: u64, _: Option<u64>) {}

macro_rules! instruction_table {
    ($($opcode:expr => $name:ident;)+) => {
        pub const INSTRUCTION_TABLE: [fn(&mut crate::State, u64, Option<u64>); u8::MAX as usize] = {
            let mut table: [fn(&mut crate::State, u64, Option<u64>); u8::MAX as usize] = [noop; u8::MAX as usize];
            $(table[$opcode as usize] = $name;)+
            table
        };

        pub const INSTRUCTION_NAME_TABLE: [&str; u8::MAX as usize] = {
            let mut table: [&str; u8::MAX as usize] = ["unknown"; u8::MAX as usize];
            $(table[$opcode as usize] = stringify!($name);)+
            table
        };
    };
}

instruction_table! {
    BPF_ADD | BPF_X | BPF_ALU =>   add_src_32;
    BPF_ADD | BPF_X | BPF_ALU64 => add_src_64;
    BPF_ADD | BPF_K | BPF_ALU =>   add_imm_32;
    BPF_ADD | BPF_K | BPF_ALU64 => add_imm_64;

    BPF_SUB | BPF_X | BPF_ALU =>   sub_src_32;
    BPF_SUB | BPF_X | BPF_ALU64 => sub_src_64;
    BPF_SUB | BPF_K | BPF_ALU =>   sub_imm_32;
    BPF_SUB | BPF_K | BPF_ALU64 => sub_imm_64;

    BPF_MUL | BPF_X | BPF_ALU =>   mul_src_32;
    BPF_MUL | BPF_X | BPF_ALU64 => mul_src_64;
    BPF_MUL | BPF_K | BPF_ALU =>   mul_imm_32;
    BPF_MUL | BPF_K | BPF_ALU64 => mul_imm_64;

    BPF_DIV | BPF_X | BPF_ALU =>   div_src_32;
    BPF_DIV | BPF_X | BPF_ALU64 => div_src_64;
    BPF_DIV | BPF_K | BPF_ALU =>   div_imm_32;
    BPF_DIV | BPF_K | BPF_ALU64 => div_imm_64;

    BPF_OR | BPF_X | BPF_ALU =>   or_src_32;
    BPF_OR | BPF_X | BPF_ALU64 => or_src_64;
    BPF_OR | BPF_K | BPF_ALU =>   or_imm_32;
    BPF_OR | BPF_K | BPF_ALU64 => or_imm_64;

    BPF_AND | BPF_X | BPF_ALU =>   and_src_32;
    BPF_AND | BPF_X | BPF_ALU64 => and_src_64;
    BPF_AND | BPF_K | BPF_ALU =>   and_imm_32;
    BPF_AND | BPF_K | BPF_ALU64 => and_imm_64;

    BPF_LSH | BPF_X | BPF_ALU =>   lsh_src_32;
    BPF_LSH | BPF_X | BPF_ALU64 => lsh_src_64;
    BPF_LSH | BPF_K | BPF_ALU =>   lsh_imm_32;
    BPF_LSH | BPF_K | BPF_ALU64 => lsh_imm_64;

    BPF_RSH | BPF_X | BPF_ALU =>   rsh_src_32;
    BPF_RSH | BPF_X | BPF_ALU64 => rsh_src_64;
    BPF_RSH | BPF_K | BPF_ALU =>   rsh_imm_32;
    BPF_RSH | BPF_K | BPF_ALU64 => rsh_imm_64;

    BPF_NEG | BPF_X | BPF_ALU =>   neg_src_32;
    BPF_NEG | BPF_X | BPF_ALU64 => neg_src_64;
    BPF_NEG | BPF_K | BPF_ALU =>   neg_imm_32_64;
    BPF_NEG | BPF_K | BPF_ALU64 => neg_imm_32_64;

    BPF_MOD | BPF_X | BPF_ALU =>   mod_src_32;
    BPF_MOD | BPF_X | BPF_ALU64 => mod_src_64;
    BPF_MOD | BPF_K | BPF_ALU =>   mod_imm_32;
    BPF_MOD | BPF_K | BPF_ALU64 => mod_imm_64;

    BPF_XOR | BPF_X | BPF_ALU =>   xor_src_32;
    BPF_XOR | BPF_X | BPF_ALU64 => xor_src_64;
    BPF_XOR | BPF_K | BPF_ALU =>   xor_imm_32;
    BPF_XOR | BPF_K | BPF_ALU64 => xor_imm_64;

    BPF_MOV | BPF_X | BPF_ALU =>   mov_src_32;
    BPF_MOV | BPF_X | BPF_ALU64 => mov_src_64;
    BPF_MOV | BPF_K | BPF_ALU =>   mov_imm_32_64;
    BPF_MOV | BPF_K | BPF_ALU64 => mov_imm_32_64;

    BPF_ARSH | BPF_X | BPF_ALU =>   arsh_src_32;
    BPF_ARSH | BPF_X | BPF_ALU64 => arsh_src_64;
    BPF_ARSH | BPF_K | BPF_ALU =>   arsh_imm_32;
    BPF_ARSH | BPF_K | BPF_ALU64 => arsh_imm_64;

    BPF_END | BPF_TO_LE | BPF_ALU => le;
    BPF_END | BPF_TO_BE | BPF_ALU => be;

    BPF_JA | BPF_K | BPF_JMP32 => ja_32;
    BPF_JA | BPF_K | BPF_JMP =>   ja_64;

    BPF_JEQ | BPF_X | BPF_JMP32 => jeq_src_32;
    BPF_JEQ | BPF_K | BPF_JMP32 => jeq_imm_32;
    BPF_JEQ | BPF_X | BPF_JMP =>   jeq_src_64;
    BPF_JEQ | BPF_K | BPF_JMP =>   jeq_imm_64;

    BPF_JGT | BPF_X | BPF_JMP32 => jgt_src_32;
    BPF_JGT | BPF_K | BPF_JMP32 => jgt_imm_32;
    BPF_JGT | BPF_X | BPF_JMP =>   jgt_src_64;
    BPF_JGT | BPF_K | BPF_JMP =>   jgt_imm_64;

    BPF_JGE | BPF_X | BPF_JMP32 => jge_src_32;
    BPF_JGE | BPF_K | BPF_JMP32 => jge_imm_32;
    BPF_JGE | BPF_X | BPF_JMP =>   jge_src_64;
    BPF_JGE | BPF_K | BPF_JMP =>   jge_imm_64;

    BPF_JSET | BPF_X | BPF_JMP32 => jset_src_32;
    BPF_JSET | BPF_K | BPF_JMP32 => jset_imm_32;
    BPF_JSET | BPF_X | BPF_JMP =>   jset_src_64;
    BPF_JSET | BPF_K | BPF_JMP =>   jset_imm_64;

    BPF_JNE | BPF_X | BPF_JMP32 => jne_src_32;
    BPF_JNE | BPF_K | BPF_JMP32 => jne_imm_32;
    BPF_JNE | BPF_X | BPF_JMP =>   jne_src_64;
    BPF_JNE | BPF_K | BPF_JMP =>   jne_imm_64;

    BPF_JSGT | BPF_X | BPF_JMP32 => jsgt_src_32;
    BPF_JSGT | BPF_K | BPF_JMP32 => jsgt_imm_32;
    BPF_JSGT | BPF_X | BPF_JMP =>   jsgt_src_64;
    BPF_JSGT | BPF_K | BPF_JMP =>   jsgt_imm_64;

    BPF_JSGE | BPF_X | BPF_JMP32 => jsge_src_32;
    BPF_JSGE | BPF_K | BPF_JMP32 => jsge_imm_32;
    BPF_JSGE | BPF_X | BPF_JMP =>   jsge_src_64;
    BPF_JSGE | BPF_K | BPF_JMP =>   jsge_imm_64;

    BPF_JLT | BPF_X | BPF_JMP32 => jlt_src_32;
    BPF_JLT | BPF_K | BPF_JMP32 => jlt_imm_32;
    BPF_JLT | BPF_X | BPF_JMP =>   jlt_src_64;
    BPF_JLT | BPF_K | BPF_JMP =>   jlt_imm_64;

    BPF_JLE | BPF_X | BPF_JMP32 => jle_src_32;
    BPF_JLE | BPF_K | BPF_JMP32 => jle_imm_32;
    BPF_JLE | BPF_X | BPF_JMP =>   jle_src_64;
    BPF_JLE | BPF_K | BPF_JMP =>   jle_imm_64;

    BPF_JSLT | BPF_X | BPF_JMP32 => jslt_src_32;
    BPF_JSLT | BPF_K | BPF_JMP32 => jslt_imm_32;
    BPF_JSLT | BPF_X | BPF_JMP =>   jslt_src_64;
    BPF_JSLT | BPF_K | BPF_JMP =>   jslt_imm_64;

    BPF_JSLE | BPF_X | BPF_JMP32 => jsle_src_32;
    BPF_JSLE | BPF_K | BPF_JMP32 => jsle_imm_32;
    BPF_JSLE | BPF_X | BPF_JMP =>   jsle_src_64;
    BPF_JSLE | BPF_K | BPF_JMP =>   jsle_imm_64;

    BPF_CALL | BPF_K | BPF_JMP => jmp_call;
    BPF_EXIT | BPF_K | BPF_JMP => exit;

    MODE_MEM | SIZE_W | BPF_LDX => ldx_mem_w;
    MODE_MEM | SIZE_W | BPF_STX => stx_mem_w;

    MODE_MEM | SIZE_H | BPF_LDX => ldx_mem_h;
    MODE_MEM | SIZE_H | BPF_STX => stx_mem_h;

    MODE_MEM | SIZE_B | BPF_LDX => ldx_mem_b;
    MODE_MEM | SIZE_B | BPF_STX => stx_mem_b;

    MODE_MEM | SIZE_DW | BPF_LDX => ldx_mem_dw;
    MODE_MEM | SIZE_DW | BPF_STX => stx_mem_dw;
}
