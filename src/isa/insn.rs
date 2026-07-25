use super::{alu::*, jmp::*, mem::*, *};

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Insn(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    W32,
    W64,
}

impl Width {
    pub fn bits(self) -> u32 {
        match self {
            Self::W32 => 32,
            Self::W64 => 64,
        }
    }

    pub fn is_32(self) -> bool {
        matches!(self, Self::W32)
    }

    pub fn reg_prefix(self) -> &'static str {
        match self {
            Self::W32 => "w",
            Self::W64 => "r",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Src {
    Reg(u8),
    Imm(i32),
}

impl Src {
    pub fn reg(self) -> Option<u8> {
        match self {
            Self::Reg(reg) => Some(reg),
            Self::Imm(_) => None,
        }
    }

    pub fn imm(self) -> Option<i32> {
        match self {
            Self::Imm(imm) => Some(imm),
            Self::Reg(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemSize {
    Byte,
    Half,
    Word,
    Dword,
}

impl MemSize {
    pub const MAX_BYTES: u32 = Self::Dword.bytes();

    pub const fn bytes(self) -> u32 {
        match self {
            Self::Byte => 1,
            Self::Half => 2,
            Self::Word => 4,
            Self::Dword => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemMode {
    Imm,
    Abs,
    Ind,
    Mem,
    Memsx,
    Atomic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallKind {
    Helper(i32),
    Subprog(i32),
    Kfunc(i32),
    Unknown,
}

impl Insn {
    pub const BYTES: usize = size_of::<Self>();

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

    pub fn class(&self) -> u8 {
        self.opcode() & 0b111
    }

    pub fn with_src_reg(&mut self, src_reg: u8) {
        self.0 = (self.0 & !(0xF << 12)) | ((src_reg as u64 & 0xF) << 12);
    }
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

    pub fn is_swap(&self) -> bool {
        let op = self.opcode();
        op == BPF_ALU32 | BPF_TO_LE | BPF_END
            || op == BPF_ALU32 | BPF_TO_BE | BPF_END
            || op == BPF_ALU64 | BPF_END
    }

    pub fn is_jmp(&self) -> bool {
        matches!(self.class(), BPF_JMP | BPF_JMP32)
    }

    pub fn width(&self) -> Width {
        match self.class() {
            BPF_ALU32 | BPF_JMP32 => Width::W32,
            _ => Width::W64,
        }
    }

    pub fn source(&self) -> Option<Src> {
        let reg_or_imm = if self.opcode() & BPF_X == BPF_X {
            Src::Reg(self.src_reg())
        } else {
            Src::Imm(self.imm())
        };

        match self.class() {
            BPF_ALU32 | BPF_ALU64 if self.is_swap() => None,
            BPF_ALU32 | BPF_ALU64 => Some(reg_or_imm),
            BPF_LDX | BPF_STX => Some(Src::Reg(self.src_reg())),
            BPF_ST => Some(Src::Imm(self.imm())),
            BPF_JMP | BPF_JMP32 => match self.opcode() & JMP_OP_MASK {
                BPF_JA | BPF_CALL | BPF_EXIT => None,
                _ => Some(reg_or_imm),
            },
            _ => None,
        }
    }

    pub fn mem_size(&self) -> MemSize {
        match self.opcode() & LOAD_SIZE_MASK {
            SIZE_B => MemSize::Byte,
            SIZE_H => MemSize::Half,
            SIZE_W => MemSize::Word,
            _ => MemSize::Dword,
        }
    }

    pub fn mem_mode(&self) -> Option<MemMode> {
        Some(match self.opcode() & LOAD_MODE_MASK {
            MODE_IMM => MemMode::Imm,
            MODE_ABS => MemMode::Abs,
            MODE_IND => MemMode::Ind,
            MODE_MEM => MemMode::Mem,
            MODE_MEMSX => MemMode::Memsx,
            MODE_ATOMIC => MemMode::Atomic,
            _ => return None,
        })
    }

    pub fn call_kind(&self) -> Option<CallKind> {
        if !self.is_jmp() || self.opcode() & JMP_OP_MASK != BPF_CALL {
            return None;
        }

        Some(match self.src_reg() {
            BPF_HELPER_CALL => CallKind::Helper(self.imm()),
            BPF_PSEUDO_CALL => CallKind::Subprog(self.imm()),
            BPF_PSEUDO_KFUNC_CALL => CallKind::Kfunc(self.imm()),
            _ => CallKind::Unknown,
        })
    }

    pub fn is_pseudo_call(&self) -> bool {
        matches!(self.call_kind(), Some(CallKind::Subprog(_)))
    }

    pub fn jump_offset(&self) -> Option<i32> {
        if !self.is_jmp() {
            return None;
        }

        match self.opcode() & JMP_OP_MASK {
            BPF_JA if self.width().is_32() => Some(self.imm()),
            BPF_JA => Some(self.offset() as i32),
            BPF_CALL => match self.call_kind() {
                Some(CallKind::Subprog(off)) => Some(off),
                _ => None,
            },
            BPF_EXIT => None,
            _ => Some(self.offset() as i32),
        }
    }

    pub fn jump_target(&self, pc: usize) -> Option<isize> {
        self.jump_offset().map(|off| pc as isize + 1 + off as isize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::jmp::{BPF_JEQ, BPF_JGT};

    fn insn(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Insn {
        Insn(
            opcode as u64
                | ((dst as u64 & 0xF) << 8)
                | ((src as u64 & 0xF) << 12)
                | ((offset as u16 as u64) << 16)
                | ((imm as u32 as u64) << 32),
        )
    }

    #[test]
    fn fields_round_trip() {
        let i = insn(BPF_ALU64 | BPF_X, 9, 3, -2, -7);
        assert_eq!(i.opcode(), BPF_ALU64 | BPF_X);
        assert_eq!(i.dst_reg(), 9);
        assert_eq!(i.src_reg(), 3);
        assert_eq!(i.offset(), -2);
        assert_eq!(i.imm(), -7);
        assert_eq!(i.class(), BPF_ALU64);

        let mut i = i;
        i.with_src_reg(10);
        i.with_imm(i32::MIN);
        assert_eq!(i.src_reg(), 10);
        assert_eq!(i.imm(), i32::MIN);
        assert_eq!(i.dst_reg(), 9);
        assert_eq!(i.offset(), -2);
    }

    #[test]
    fn width_follows_class() {
        let cases = [
            (BPF_ALU32 | BPF_K, Width::W32),
            (BPF_ALU64 | BPF_K, Width::W64),
            (BPF_JMP32 | BPF_K, Width::W32),
            (BPF_JMP | BPF_K, Width::W64),
            (BPF_LDX | SIZE_W | MODE_MEM, Width::W64),
            (BPF_ST | SIZE_B | MODE_MEM, Width::W64),
        ];

        for (opcode, expected) in cases {
            assert_eq!(insn(opcode, 0, 0, 0, 0).width(), expected, "{opcode:#x}");
        }

        assert_eq!(Width::W32.bits(), 32);
        assert_eq!(Width::W64.bits(), 64);
        assert!(Width::W32.is_32());
        assert!(!Width::W64.is_32());
        assert_eq!(Width::W32.reg_prefix(), "w");
        assert_eq!(Width::W64.reg_prefix(), "r");
    }

    #[test]
    fn source_operand() {
        let cases = [
            (BPF_ALU64 | BPF_X, Some(Src::Reg(4))),
            (BPF_ALU32 | BPF_K, Some(Src::Imm(77))),
            (BPF_LDX | SIZE_W | MODE_MEM, Some(Src::Reg(4))),
            (BPF_STX | SIZE_W | MODE_MEM, Some(Src::Reg(4))),
            (BPF_ST | SIZE_W | MODE_MEM, Some(Src::Imm(77))),
            (BPF_JMP | BPF_X | BPF_JEQ, Some(Src::Reg(4))),
            (BPF_JMP32 | BPF_K | BPF_JEQ, Some(Src::Imm(77))),
            (BPF_JMP | BPF_K | BPF_JA, None),
            (BPF_JMP32 | BPF_K | BPF_JA, None),
            (BPF_JMP | BPF_K | BPF_CALL, None),
            (BPF_JMP | BPF_K | BPF_EXIT, None),
            (BPF_LD | MODE_IMM | SIZE_DW, None),
        ];

        for (opcode, expected) in cases {
            assert_eq!(insn(opcode, 1, 4, 0, 77).source(), expected, "{opcode:#x}");
        }
    }

    #[test]
    fn source_helpers() {
        assert_eq!(Src::Reg(6).reg(), Some(6));
        assert_eq!(Src::Reg(6).imm(), None);
        assert_eq!(Src::Imm(-1).imm(), Some(-1));
        assert_eq!(Src::Imm(-1).reg(), None);
    }

    #[test]
    fn byte_swap_has_no_source() {
        let be = insn(BPF_ALU32 | BPF_TO_BE | BPF_END, 1, 0, 0, 16);
        let le = insn(BPF_ALU32 | BPF_TO_LE | BPF_END, 1, 0, 0, 16);
        let swap = insn(BPF_ALU64 | BPF_END, 1, 0, 0, 16);

        assert!(be.is_swap() && le.is_swap() && swap.is_swap());
        assert_eq!(be.source(), None);
        assert_eq!(le.source(), None);
        assert_eq!(swap.source(), None);
    }

    #[test]
    fn memory_size_and_mode() {
        let cases = [
            (SIZE_B, MemSize::Byte, 1),
            (SIZE_H, MemSize::Half, 2),
            (SIZE_W, MemSize::Word, 4),
            (SIZE_DW, MemSize::Dword, 8),
        ];

        for (size, expected, bytes) in cases {
            let i = insn(BPF_LDX | size | MODE_MEM, 0, 0, 0, 0);
            assert_eq!(i.mem_size(), expected, "{size:#x}");
            assert_eq!(i.mem_size().bytes(), bytes);
        }

        let modes = [
            (MODE_IMM, Some(MemMode::Imm)),
            (MODE_ABS, Some(MemMode::Abs)),
            (MODE_IND, Some(MemMode::Ind)),
            (MODE_MEM, Some(MemMode::Mem)),
            (MODE_MEMSX, Some(MemMode::Memsx)),
            (MODE_ATOMIC, Some(MemMode::Atomic)),
            (0x5 << 5, None),
            (0x7 << 5, None),
        ];

        for (mode, expected) in modes {
            let i = insn(BPF_LDX | SIZE_W | mode, 0, 0, 0, 0);
            assert_eq!(i.mem_mode(), expected, "{mode:#x}");
        }
    }

    #[test]
    fn call_kinds() {
        let call = |src| insn(BPF_JMP | BPF_K | BPF_CALL, 0, src, 0, 42);

        assert_eq!(
            call(BPF_HELPER_CALL).call_kind(),
            Some(CallKind::Helper(42))
        );
        assert_eq!(
            call(BPF_PSEUDO_CALL).call_kind(),
            Some(CallKind::Subprog(42))
        );
        assert_eq!(
            call(BPF_PSEUDO_KFUNC_CALL).call_kind(),
            Some(CallKind::Kfunc(42))
        );
        assert_eq!(call(7).call_kind(), Some(CallKind::Unknown));

        assert!(call(BPF_PSEUDO_CALL).is_pseudo_call());
        assert!(!call(BPF_HELPER_CALL).is_pseudo_call());

        assert_eq!(
            insn(BPF_JMP | BPF_K | BPF_EXIT, 0, 0, 0, 0).call_kind(),
            None
        );
        assert_eq!(insn(BPF_ALU64 | BPF_K, 0, 0, 0, 42).call_kind(), None);
    }

    #[test]
    fn jump_offsets() {
        let cases = [
            (insn(BPF_JMP | BPF_K | BPF_JA, 0, 0, -3, 9), Some(-3)),
            (insn(BPF_JMP32 | BPF_K | BPF_JA, 0, 0, -3, 9), Some(9)),
            (insn(BPF_JMP | BPF_X | BPF_JEQ, 1, 2, 5, 0), Some(5)),
            (insn(BPF_JMP32 | BPF_K | BPF_JGT, 1, 0, 5, 0), Some(5)),
            (
                insn(BPF_JMP | BPF_K | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 12),
                Some(12),
            ),
            (
                insn(BPF_JMP | BPF_K | BPF_CALL, 0, BPF_HELPER_CALL, 0, 12),
                None,
            ),
            (insn(BPF_JMP | BPF_K | BPF_EXIT, 0, 0, 0, 0), None),
            (insn(BPF_ALU64 | BPF_K, 0, 0, 4, 0), None),
        ];

        for (i, expected) in cases {
            assert_eq!(i.jump_offset(), expected, "{:#x}", i.opcode());
        }
    }

    #[test]
    fn jump_targets_are_relative_to_the_next_insn() {
        let fwd = insn(BPF_JMP | BPF_X | BPF_JEQ, 1, 2, 5, 0);
        assert_eq!(fwd.jump_target(10), Some(16));

        let back = insn(BPF_JMP | BPF_K | BPF_JA, 0, 0, -4, 0);
        assert_eq!(back.jump_target(10), Some(7));
        assert_eq!(back.jump_target(0), Some(-3));

        assert_eq!(
            insn(BPF_JMP | BPF_K | BPF_EXIT, 0, 0, 0, 0).jump_target(3),
            None
        );
    }
}
