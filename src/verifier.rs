use std::{collections::BTreeMap, ops::Range, sync::Arc};

use crate::{
    btf::{BtfKind, BtfTypeId},
    isa::{alu::*, jmp::*, load::*, *},
    object::EbpfProgram,
    vm::Vm,
};

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("too many context arguments: {0} > 5")]
    TooManyContextArguments(usize),
    #[error("context argument type not supported: {ty:?}")]
    UnsupportedContextType { arg_id: usize, ty: BtfTypeId },
    #[error(
        "{insn_off}: {} - {}: {msg}",
        crate::isa::INSTRUCTION_NAME_TABLE[insn.opcode() as usize],
        crate::vm::debugger::disasm(*insn, None)
    )]
    Other {
        insn: Insn,
        insn_off: usize,
        msg: &'static str,
    },
}

macro_rules! guard {
    ($vm:ident, $m:literal) => {
        return Err($vm.err($m))
    };
    ($vm:ident, $e:expr, $m:literal) => {
        if !$e {
            guard!($vm, $m)
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterState {
    Uninit,
    Scalar(Scalar),
    PtrToCtx {
        offset: u32,
        size: u32,
    },
    PtrToStack {
        pointer: u32,
    },
    PtrToMap {
        map_fd: i32,
    },
    /// A non-null pointer to a map value, returned by map_lookup_elem.
    /// Either returned by an array or refined through a check against NULL.
    PtrToMapValue {
        map_fd: i32,
        offset: u32,
    },
    /// Pointer to a map value or NULL. Returned by map_lookup_elem.
    /// Arrays never return null.
    ///
    /// In order to be used, it must be refined by checking against NULL.
    /// It's then transformed into a [`RegisterState::PtrToMapValue`]
    PtrToMapValueOrNull {
        map_fd: i32,
    },
}

/// Known scalar representation.
///
/// Scalar values are most frequently not exact. The verifier
/// sees them as ranges. Values that exist from A to B, sometimes
/// stepped. These ranges are _refined_ when performing jumps,
/// adjusted to be wider or narrower. Arithmetic operations can
/// expand or contract them, adds perform offsets in the range
/// (min + VAL, max + VAL), shifts change the _stride_ (interval
/// between numbers in the range, or step).
///
/// The verifier uses this information to validate pointer accesses, predict
/// branch executions, etc.
///
/// Let's illustrate what happens:
/// ```asm
/// 1: u16 arr = [0..64];
/// 2: if r0 < 1 goto done   ; r0 = Range { min: 1, max: u32::MAX, stride: 1 }
/// 3: r0 += 1               ; r0 = Range { min: 2, max: u32::MAX + 1, stride: 1 }
///                          ; max wraps here, next line will fix this
/// 4: if r0 >= 64 goto done ; r0 = Range { min: 2, max: 63, stride: 1 }
/// 5: r0 = r0 << 1          ; r0 = Range { min: 4, max: 126, stride: 2 }
/// 6: r1 = arr[r0]          ; verifier ensures r0.min and r0.max are within ranges,
///                          ; and that r0.stride is aligns to elements
/// 7: done: exit
/// ```
/// When accessing an array, the verifier must guarantee the code won't
/// perform an out-of-bounds execution. By gating the code in line 2 and 4,
/// the verifier ensures the access will happen within `arr` bounds. In line 3,
/// we expand the range to +1. Note that the array contains u16 elements,
/// two bytes in size, so we adjust it to u16 boundaries in line 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalarRange<T: Copy> {
    pub min: T,
    pub max: T,
    pub stride: T,
}

impl<T: Copy + PartialEq + PartialOrd> ScalarRange<T> {
    pub fn single_val(&self) -> Option<T> {
        (self.min == self.max).then_some(self.min)
    }
    pub fn contains(&self, val: T) -> bool {
        val >= self.min && val <= self.max
    }
    pub fn overlap(&self, other: &Self) -> bool {
        self.min <= other.max && other.min <= self.max
    }
}

impl<T: Copy + From<u8>> ScalarRange<T> {
    pub fn exact(val: T) -> Self {
        Self {
            min: val,
            max: val,
            stride: T::from(1),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    U32(ScalarRange<u32>),
    U64(ScalarRange<u64>),
    Unknown,
}

impl ScalarRange<u32> {
    fn wrapping_offset(self, val: u32, op: fn(u32, u32) -> u32, src_abs: u64) -> Self {
        ScalarRange {
            min: op(self.min, val),
            max: op(self.max, val),
            stride: if src_abs.is_multiple_of(self.stride as u64) {
                self.stride
            } else {
                1
            },
        }
    }

    fn shift_to_u64(self, shift: u32, shl: bool) -> ScalarRange<u64> {
        let (op, overflow): (fn(u64, u32) -> Option<u64>, u64) = if shl {
            (u64::checked_shl, u64::MAX)
        } else {
            (u64::checked_shr, 0)
        };
        ScalarRange {
            min: op(self.min as u64, shift).unwrap_or(overflow),
            max: op(self.max as u64, shift).unwrap_or(overflow),
            stride: if shl {
                (self.stride as u64).checked_shl(shift).unwrap_or(1)
            } else {
                (self.stride as u64).checked_shr(shift).unwrap_or(1).max(1)
            },
        }
    }

    fn arsh_to_u64(self, shift: u32) -> ScalarRange<u64> {
        let a = ((self.min as i32 as i64) >> shift) as u64;
        let b = ((self.max as i32 as i64) >> shift) as u64;
        ScalarRange {
            min: a.min(b),
            max: a.max(b),
            stride: (self.stride as u64).checked_shr(shift).unwrap_or(1).max(1),
        }
    }
}

impl ScalarRange<u64> {
    fn wrapping_offset(self, val: u64, op: fn(u64, u64) -> u64, src_abs: u64) -> Self {
        ScalarRange {
            min: op(self.min, val),
            max: op(self.max, val),
            stride: if src_abs.is_multiple_of(self.stride) {
                self.stride
            } else {
                1
            },
        }
    }

    fn shift(self, shift: u32, shl: bool) -> Self {
        let (op, overflow): (fn(u64, u32) -> Option<u64>, u64) = if shl {
            (u64::checked_shl, u64::MAX)
        } else {
            (u64::checked_shr, 0)
        };
        ScalarRange {
            min: op(self.min, shift).unwrap_or(overflow),
            max: op(self.max, shift).unwrap_or(overflow),
            stride: if shl {
                self.stride.checked_shl(shift).unwrap_or(1)
            } else {
                self.stride.checked_shr(shift).unwrap_or(1).max(1)
            },
        }
    }

    fn arsh(self, shift: u32) -> Self {
        let a = ((self.min as i64) >> shift) as u64;
        let b = ((self.max as i64) >> shift) as u64;
        ScalarRange {
            min: a.min(b),
            max: a.max(b),
            stride: self.stride.checked_shr(shift).unwrap_or(1).max(1),
        }
    }

    /// Exclude a boundary value from this range. If `val` equals min,
    /// the range shrinks from below; if it equals max, from above.
    /// Interior values don't change the range (we can't represent
    /// a hole). Returns None when the exclusion empties the range.
    fn exclude(self, val: u64) -> Option<Self> {
        if val == self.min {
            let new_min = self.min + self.stride;
            if new_min > self.max {
                None
            } else {
                Some(Self {
                    min: new_min,
                    ..self
                })
            }
        } else if val == self.max && self.max >= self.stride && self.max - self.stride >= self.min {
            Some(Self {
                max: self.max - self.stride,
                ..self
            })
        } else {
            Some(self)
        }
    }
}

impl Scalar {
    fn is_known(&self) -> bool {
        match self {
            Self::U32(r) => r.single_val().is_some(),
            Self::U64(r) => r.single_val().is_some(),
            Self::Unknown => false,
        }
    }

    fn alu_add(self, src_val: i64) -> Option<Self> {
        match self {
            Self::U32(r) => Some(Self::U32(r.wrapping_offset(
                src_val as u32,
                u32::wrapping_add,
                src_val.unsigned_abs(),
            ))),
            Self::U64(r) => Some(Self::U64(r.wrapping_offset(
                src_val as u64,
                u64::wrapping_add,
                src_val.unsigned_abs(),
            ))),
            _ => None,
        }
    }

    fn alu_sub(self, src_val: i64) -> Option<Self> {
        match self {
            Self::U32(r) => Some(Self::U32(r.wrapping_offset(
                src_val as u32,
                u32::wrapping_sub,
                src_val.unsigned_abs(),
            ))),
            Self::U64(r) => Some(Self::U64(r.wrapping_offset(
                src_val as u64,
                u64::wrapping_sub,
                src_val.unsigned_abs(),
            ))),
            _ => None,
        }
    }

    fn alu_lsh(self, src_val: i64) -> Option<Self> {
        let shift = src_val as u32;
        match self {
            Self::U32(r) => Some(Self::U64(r.shift_to_u64(shift, true))),
            Self::U64(r) => Some(Self::U64(r.shift(shift, true))),
            _ => None,
        }
    }

    fn alu_rsh(self, src_val: i64) -> Option<Self> {
        let shift = src_val as u32;
        match self {
            Self::U32(r) => Some(Self::U64(r.shift_to_u64(shift, false))),
            Self::U64(r) => Some(Self::U64(r.shift(shift, false))),
            _ => None,
        }
    }

    fn alu_arsh(self, src_val: i64) -> Option<Self> {
        let shift = src_val as u32;
        match self {
            Self::U32(r) => Some(Self::U64(r.arsh_to_u64(shift))),
            Self::U64(r) => Some(Self::U64(r.arsh(shift))),
            _ => None,
        }
    }
}

impl RegisterState {
    fn is_uninint(&self) -> bool {
        matches!(self, Self::Uninit)
    }

    pub fn is_pointer(&self) -> bool {
        match self {
            RegisterState::PtrToCtx { .. }
            | RegisterState::PtrToStack { .. }
            | RegisterState::PtrToMap { .. }
            | RegisterState::PtrToMapValue { .. }
            | RegisterState::PtrToMapValueOrNull { .. } => true,
            RegisterState::Uninit | RegisterState::Scalar { .. } => false,
        }
    }
}

pub struct VerifierConfig {
    pub max_insns: usize,
    pub max_ctx_params: usize,
    pub max_loops: usize,
    pub allow_unreachable: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_insns: u16::MAX as usize,
            max_ctx_params: 1,
            max_loops: 0,
            allow_unreachable: false,
        }
    }
}

#[derive(Clone)]
pub struct Verifier<'a> {
    vm: &'a Vm,
    prog: Arc<EbpfProgram>,
}

#[derive(Clone)]
pub struct VerifierState<'a> {
    vm: &'a Vm,
    prog: Arc<EbpfProgram>,
    registers: [RegisterState; 11],
    starting_pc: isize,
    pc: isize,
    skip: usize,
    exit: bool,

    stack_objects: BTreeMap<u32, (u32, RegisterState)>,
    stack_range: Range<u32>,
    indent: usize,
}

impl<'a> VerifierState<'a> {
    pub fn new(vm: &'a Vm, prog: Arc<EbpfProgram>) -> Result<Self, VerifierError> {
        if prog.sig.params_types.len() > 5 {
            return Err(VerifierError::TooManyContextArguments(
                prog.sig.params_types.len(),
            ));
        }

        let mut registers = [RegisterState::Uninit; 11];

        for (idx, (_, ty)) in prog.sig.params_types.iter().enumerate() {
            let btf = prog.btf.as_ref().unwrap();
            let btf_type = btf.get_type(*ty).unwrap();
            let size = btf_type.kind.size(btf).unwrap();

            registers[idx + 1] = match btf_type.kind {
                BtfKind::Int(_) => RegisterState::Scalar(Scalar::Unknown),
                BtfKind::Ptr(_) => RegisterState::PtrToCtx { offset: 0, size },
                _ => {
                    return Err(VerifierError::UnsupportedContextType {
                        arg_id: idx,
                        ty: *ty,
                    });
                }
            };
        }

        registers[10] = RegisterState::PtrToStack { pointer: 512 };

        Ok(Self {
            vm,
            prog,
            registers,
            starting_pc: 0,
            pc: 0,
            skip: 0,
            exit: false,
            stack_objects: Default::default(),
            stack_range: (0..512),
            indent: 0,
        })
    }

    pub fn run(mut self) -> Result<(), VerifierError> {
        let prog = &self.prog.clone();
        let mut iter = prog.insns.iter().enumerate().skip(self.pc as usize);

        while let Some((idx, insn)) = iter.by_ref().skip(self.skip).next() {
            self.skip = 0;
            self.pc = idx as isize + 1;

            self.check_insn(idx, insn)?;

            if self.exit {
                break;
            }
        }

        Ok(())
    }

    fn check_insn(&mut self, idx: usize, insn: &Insn) -> Result<(), VerifierError> {
        guard!(
            self,
            insn.dst_reg() < 10 || matches!(insn.class(), BPF_ST | BPF_STX if insn.dst_reg() == 10),
            "insn with invalid src register"
        );
        guard!(self, insn.src_reg() <= 10, "insn with invalid src register");
        guard!(self, insn.dst_reg() <= 10, "insn with invalid dst register");

        let pad = " ".repeat(self.indent * 4);
        let name = crate::isa::INSTRUCTION_NAME_TABLE[insn.opcode() as usize];
        let disasm = crate::vm::debugger::disasm(*insn, self.prog.insns.get(idx + 1).cloned());
        let touched = self.touched_regs(insn);

        match insn.class() {
            BPF_ALU32 | BPF_ALU64 => self.check_alu(insn)?,
            BPF_LD => self.check_non_conventional_ld(insn)?,
            BPF_LDX => self.check_ldx(insn)?,
            BPF_ST | BPF_STX => self.check_st(insn)?,
            BPF_JMP32 | BPF_JMP => {
                if insn.opcode() & JMP_OP_MASK != BPF_EXIT {
                    let dump = touched
                        .iter()
                        .map(|&i| format!("r{i}: {:?}", self.registers[i]))
                        .collect::<Vec<_>>()
                        .join(", ");

                    eprintln!("{pad}{idx}: {name}: {disasm} — {dump}");
                }

                self.check_jmp(insn)?
            }
            _ => {}
        }

        let dump = touched
            .iter()
            .map(|&i| format!("r{i}: {:?}", self.registers[i]))
            .collect::<Vec<_>>()
            .join(", ");

        eprintln!("{pad}{idx}: {name}: {disasm} — {dump}");

        Ok(())
    }

    fn dst_reg(&self, insn: &Insn) -> RegisterState {
        self.registers[insn.dst_reg() as usize]
    }

    fn src_reg(&self, insn: &Insn) -> Result<RegisterState, VerifierError> {
        guard!(self, insn.src_reg() <= 10, "invalid src register value");

        let jmp_op = insn.opcode() & JMP_OP_MASK;
        let is_x = insn.opcode() & BPF_X == BPF_X;

        let has_src = match insn.class() {
            BPF_ALU32 | BPF_ALU64 => is_x,
            BPF_LDX => true,
            BPF_ST | BPF_STX => insn.class() == BPF_STX,
            BPF_JMP32 | BPF_JMP if jmp_op == BPF_CALL => false,
            BPF_JMP32 | BPF_JMP => is_x,
            _ => false,
        };

        guard!(self, has_src, "instruction doesn't take src register");
        Ok(self.registers[insn.src_reg() as usize])
    }

    fn touched_regs(&self, insn: &Insn) -> Vec<usize> {
        let mut regs = Vec::new();
        let jmp_op = insn.opcode() & JMP_OP_MASK;
        let is_x = insn.opcode() & BPF_X == BPF_X;

        match insn.class() {
            BPF_ALU32 | BPF_ALU64 => {
                regs.push(insn.dst_reg() as usize);
                if is_x {
                    regs.push(insn.src_reg() as usize);
                }
            }
            BPF_LD => {
                regs.push(insn.dst_reg() as usize);
            }
            BPF_LDX => {
                regs.push(insn.dst_reg() as usize);
                regs.push(insn.src_reg() as usize);
            }
            BPF_ST | BPF_STX => {
                regs.push(insn.dst_reg() as usize);
                if insn.class() == BPF_STX {
                    regs.push(insn.src_reg() as usize);
                }
            }
            BPF_JMP32 | BPF_JMP if jmp_op == BPF_CALL => {
                regs.push(0);
            }
            BPF_JMP32 | BPF_JMP => {
                regs.push(insn.dst_reg() as usize);
                if is_x {
                    regs.push(insn.src_reg() as usize);
                }
            }
            _ => {}
        }

        regs.sort_unstable();
        regs.dedup();
        regs
    }

    fn err(&self, msg: &'static str) -> VerifierError {
        let insn_off = self.pc as usize - 1;
        let insn = self.prog.insns[insn_off];

        VerifierError::Other {
            insn,
            insn_off,
            msg,
        }
    }

    fn mark_unknown(&mut self, reg: u8) -> Result<(), VerifierError> {
        guard!(self, reg < 10, "tried marking r10 as unknown");
        self.registers[reg as usize] = RegisterState::Scalar(Scalar::Unknown);
        Ok(())
    }

    fn check_alu(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let op = insn.opcode() & ALU_OP_MASK;

        let src = if let Ok(src_state) = self.src_reg(insn) {
            guard!(self, insn.imm() == 0, "illegal reserved imm field");

            guard!(
                self,
                src_state != RegisterState::Uninit,
                "illegal uninit src register"
            );

            Some(src_state)
        } else {
            guard!(
                self,
                insn.src_reg() == 0,
                "illegal reserved src register field"
            );

            None
        };

        let size = if insn.class() == BPF_ALU32 { 32 } else { 64 };

        match (op, src) {
            (BPF_MOV, _) => return self.check_alu_mov(insn),

            (BPF_MOD | BPF_DIV, None) if insn.imm() == 0 => guard!(self, "division by IMM=0"),
            (BPF_LSH | BPF_RSH | BPF_ARSH, None) if insn.imm() < 0 || insn.imm() >= size => {
                guard!(self, "shift out of bounds");
            }

            _ => {}
        }

        guard!(
            self,
            insn.offset() == 0 || matches!(op, BPF_MOD | BPF_DIV if insn.offset() == 1),
            "illegal reserved offset field"
        );

        let dst = self.dst_reg(insn);
        guard!(
            self,
            dst != RegisterState::Uninit,
            "illegal uninit dst register"
        );

        if insn.class() != BPF_ALU64 {
            guard!(
                self,
                !dst.is_pointer() && src.is_none_or(|src| !src.is_pointer()),
                "ALU32 cannot perform pointer arithmetic"
            );

            // TODO: track scalar operations like add, sub, mul, etc
            // 32bit ALU operations produce scalars

            return self.mark_unknown(insn.dst_reg());
        }

        let (ptr, scalar) = match (dst, src) {
            (RegisterState::Scalar(_), None | Some(RegisterState::Scalar(_))) => {
                // 64bit scalar operation tracking
                return self.check_alu_scalars(insn);
            }

            (RegisterState::Scalar(dst), Some(src)) if src.is_pointer() => {
                guard!(self, op == BPF_ADD, "scalar + pointer only allowed for ADD");
                (src, dst)
            }

            (dst, None) if dst.is_pointer() => {
                (dst, Scalar::U32(ScalarRange::exact(insn.imm() as u32)))
            }
            (dst, Some(RegisterState::Scalar(src))) if dst.is_pointer() => (dst, src),

            _ => guard!(self, "illegal registers"),
        };

        let (scalar_min, scalar_max, scalar_stride) = match scalar {
            Scalar::U32(r) => (r.min as i32, r.max as i32, r.stride as i32),
            Scalar::U64(r) => (r.min as u32 as i32, r.max as u32 as i32, r.stride as i32),
            _ => guard!(self, "pointer arithmetic with unknown scalar"),
        };

        match op {
            BPF_ADD => {
                self.registers[insn.dst_reg() as usize] = match ptr {
                    RegisterState::PtrToCtx { offset, size } => {
                        let max_off = offset
                            .checked_add_signed(scalar_max)
                            .ok_or(self.err("new ptr overflows ctx"))?;
                        guard!(self, size > max_off, "new ptr overflows ctx");
                        RegisterState::PtrToCtx {
                            offset: max_off,
                            size,
                        }
                    }
                    RegisterState::PtrToStack { pointer } => {
                        let pointer = pointer
                            .checked_add_signed(scalar_min)
                            .ok_or(self.err("new ptr overflows stack"))?;
                        guard!(
                            self,
                            pointer >= self.stack_range.start,
                            "new ptr overflows stack"
                        );
                        RegisterState::PtrToStack { pointer }
                    }
                    RegisterState::PtrToMapValue { map_fd, offset } => {
                        let bpf_map = self
                            .vm
                            .map_by_fd(map_fd)
                            .ok_or(self.err("ptr to map value points to unknown map FD"))?;
                        let map_val = bpf_map
                            .spec
                            .value
                            .ok_or(self.err("ptr to map value has no associated value BTF type"))?;

                        for v in (scalar_min..=scalar_max).step_by(scalar_stride as usize) {
                            let off = offset
                                .checked_add_signed(v)
                                .ok_or(self.err("new ptr to map value overflows map"))?;
                            guard!(
                                self,
                                bpf_map.btf.is_offset_valid(map_val, off, None) == Some(true),
                                "new ptr to map value has invalid offset"
                            );
                        }

                        let max_off = offset
                            .checked_add_signed(scalar_max)
                            .ok_or(self.err("new ptr to map value overflows map"))?;
                        RegisterState::PtrToMapValue {
                            map_fd,
                            offset: max_off,
                        }
                    }
                    _ => todo!(),
                };
            }
            BPF_SUB => {
                self.registers[insn.dst_reg() as usize] = match ptr {
                    RegisterState::PtrToCtx { offset, size } => {
                        todo!();
                    }
                    RegisterState::PtrToMap { map_fd } => {
                        todo!();
                    }
                    _ => guard!(self, "invalid pointer arithmetic operation"),
                };
            }

            _ => guard!(self, "illegal pointer arithmetic operation"),
        }

        Ok(())
    }

    /// Checks ALU operations for ADD, SUB, LSH, RSH, ARSH and adjusts
    /// the registers.
    ///
    /// Known scalars are stored as ranges with a min, max, and stride fields.
    /// This function performs adjustments on both ends, min and max, and adjusts
    /// the stride when needed.
    ///
    /// For now, we only adjust if SRC represents a single value, either the immediate
    /// or a scalar with min==max.
    ///
    /// * ADD/SUB keeps the stride if the absolute SRC value is a multiple of it, otherwise resets to 1.
    /// * LSH shifts the stride to the left. On overflow, it resets to 1.
    /// * RSH/ARSH shifts the stride to the right. On underflow, it resets to 1.
    ///
    /// If SRC is a range or if an operation fails for any reason, DST is marked as unknown.
    ///
    /// Ref: <https://github.com/torvalds/linux/blob/ea1013c1539270e372fc99854bc6e4d94eaeff66/kernel/bpf/verifier.c#L15505>
    fn check_alu_scalars(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let src_val = match self.src_reg(insn) {
            Ok(RegisterState::Scalar(Scalar::U32(r))) => match r.single_val() {
                Some(v) => v as i32 as i64,
                None => return self.mark_unknown(insn.dst_reg()),
            },
            Err(_) => insn.imm() as i64,
            _ => return self.mark_unknown(insn.dst_reg()),
        };

        // TODO: track scalar operations like mul, neg, and, or, xor
        let alu_fn = match insn.opcode() & ALU_OP_MASK {
            BPF_ADD => Scalar::alu_add,
            BPF_SUB => Scalar::alu_sub,
            BPF_LSH => Scalar::alu_lsh,
            BPF_RSH => Scalar::alu_rsh,
            BPF_ARSH => Scalar::alu_arsh,
            _ => return self.mark_unknown(insn.dst_reg()),
        };

        if let RegisterState::Scalar(s) = self.dst_reg(insn) {
            if let Some(result) = alu_fn(s, src_val) {
                self.registers[insn.dst_reg() as usize] = RegisterState::Scalar(result);
                Ok(())
            } else {
                self.mark_unknown(insn.dst_reg())
            }
        } else {
            self.mark_unknown(insn.dst_reg())
        }
    }

    /// Checks an ALU MOV instruction and updates registers.
    ///
    /// * Moving a pointer simply copies the pointer to DST,
    /// only ALU64 can perform pointer moves.
    /// * When moving known scalars, the value is trimmed
    /// according to the ALU class. If the insn is a MOVSX (sign-extension),
    /// the offset is checked and the known value is sign-extended
    /// accordingly.
    /// * Moving unknown scalars simply copy the unknown status.
    /// * Moving IMMs result in known scalars with size according to the class.
    fn check_alu_mov(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        self.registers[insn.dst_reg() as usize] = match self.src_reg(insn) {
            Ok(src) if src.is_pointer() => {
                guard!(self, insn.class() == BPF_ALU64, "partial copy of pointer");
                guard!(self, insn.offset() == 0, "sign extension on pointer");

                src
            }
            Ok(RegisterState::Scalar(scalar)) if scalar.is_known() => {
                let scalar = match (insn.class(), scalar) {
                    (BPF_ALU32, Scalar::U64(r)) => Scalar::U32(ScalarRange::exact(r.min as u32)),
                    (BPF_ALU64, Scalar::U32(r)) => Scalar::U64(ScalarRange::exact(r.min as u64)),
                    _ => scalar,
                };

                let scalar = match (insn.offset() as u32, scalar) {
                    (0, _) => scalar,
                    (offset @ (8 | 16), Scalar::U32(r)) => {
                        let shift = u32::BITS - offset;
                        Scalar::U32(ScalarRange::exact(
                            ((r.min as i32) << shift >> shift) as u32,
                        ))
                    }
                    (offset @ (8 | 16 | 32), Scalar::U64(r)) => {
                        let shift = u64::BITS - offset;
                        Scalar::U64(ScalarRange::exact(
                            ((r.min as i64) << shift >> shift) as u64,
                        ))
                    }
                    _ => guard!(self, "mov with invalid offset"),
                };

                RegisterState::Scalar(scalar)
            }
            Ok(src @ RegisterState::Scalar(_)) => src,
            Ok(_) => guard!(self, "mov with invalid src register"),
            Err(_) => {
                if insn.class() == BPF_ALU32 {
                    RegisterState::Scalar(Scalar::U32(ScalarRange::exact(insn.imm() as u32)))
                } else {
                    RegisterState::Scalar(Scalar::U64(ScalarRange::exact(insn.imm() as u64)))
                }
            }
        };

        Ok(())
    }

    fn check_ldx(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        match insn.opcode() & LOAD_MODE_MASK {
            MODE_MEM => {
                let load_size = match insn.opcode() & LOAD_SIZE_MASK {
                    SIZE_DW => 8,
                    SIZE_W => 4,
                    SIZE_H => 2,
                    SIZE_B => 1,
                    _ => unreachable!(),
                };

                match self.src_reg(insn).expect("invalid src state for LD") {
                    RegisterState::PtrToCtx { offset, size } => {
                        guard!(
                            self,
                            insn.offset() >= 0,
                            "negative offset reads are not supported yet"
                        );

                        let read_offset = offset
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("tried reading out of ctx bounds"))?;
                        guard!(
                            self,
                            read_offset + load_size <= size,
                            "tried reading out of ctx bounds"
                        );
                    }
                    RegisterState::PtrToStack { pointer } => {
                        guard!(
                            self,
                            insn.offset() < 0,
                            "negative offset reads are not supported yet"
                        );

                        let dst = pointer
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("tried reading out of stack bounds"))?;
                        let &(slot_size, saved_state) = self
                            .stack_objects
                            .get(&dst)
                            .ok_or(self.err("tried reading out of uninit stack slot"))?;
                        guard!(
                            self,
                            slot_size == load_size,
                            "load size does not match stack slot size"
                        );
                        self.registers[insn.dst_reg() as usize] = saved_state;
                    }
                    RegisterState::PtrToMap { map_fd } => todo!(),
                    RegisterState::PtrToMapValue { map_fd, offset } => {
                        guard!(
                            self,
                            insn.offset() >= 0,
                            "negative offset reads are not supported yet"
                        );

                        let bpf_map = self
                            .vm
                            .map_by_fd(map_fd)
                            .ok_or(self.err("load from unknown map FD"))?;
                        let map_val = bpf_map
                            .spec
                            .value
                            .ok_or(self.err("map has no associated value BTF type"))?;
                        let offset = offset
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("load overflows map value"))?;
                        guard!(
                            self,
                            bpf_map
                                .btf
                                .is_offset_valid(map_val, offset, Some(load_size))
                                == Some(true),
                            "tried reading from ptr to map value with invalid offset"
                        );
                    }
                    _ => guard!(self, "invalid memory location"),
                }

                return self.mark_unknown(insn.dst_reg());
            }
            MODE_MEMSX => guard!(self, "sign-extension loads are not supported yet"),
            _ => guard!(self, "unsupported load mode"),
        }
    }

    /// Checks for LD IMM64 instructions. For now,
    /// only IMM and MAP FD loads are supported. Signals
    /// for the verifier to skip next instruction.
    fn check_non_conventional_ld(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        guard!(
            self,
            insn.opcode() & LOAD_MODE_MASK == MODE_IMM,
            "ld class is reserved for ld_imm64"
        );
        guard!(
            self,
            insn.opcode() & LOAD_SIZE_MASK == SIZE_DW,
            "ld class is reserved for ld_imm64"
        );

        match insn.src_reg() {
            0 => {
                let next = self.prog.insns[self.pc as usize];
                let imm64 =
                    (insn.imm() as u64 & 0xFFFF_FFFF) | ((next.imm() as u64 & 0xFFFF_FFFF) << 32);
                self.registers[insn.dst_reg() as usize] =
                    RegisterState::Scalar(Scalar::U64(ScalarRange::exact(imm64)));
            }
            BPF_PSEUDO_MAP_FD => {
                let map_fd = insn.imm();
                guard!(
                    self,
                    self.vm.map_by_fd_exists(map_fd),
                    "referenced non-existing map FD"
                );
                self.registers[insn.dst_reg() as usize] = RegisterState::PtrToMap { map_fd }
            }
            BPF_PSEUDO_MAP_VALUE => {
                let map_fd = insn.imm();
                let next = self.prog.insns[self.pc as usize];
                let offset = next.imm() as u32;
                guard!(
                    self,
                    self.vm.map_by_fd_exists(map_fd),
                    "referenced non-existing map FD"
                );
                self.registers[insn.dst_reg() as usize] =
                    RegisterState::PtrToMapValue { map_fd, offset };
            }
            _ => guard!(self, "unsupported pseudo function"),
        }

        self.skip = 1;
        Ok(())
    }

    fn check_st(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let mode = insn.opcode() & LOAD_MODE_MASK;
        guard!(
            self,
            mode == MODE_MEM || mode == MODE_ATOMIC,
            "unsupported store mode"
        );
        let dst_reg = self.dst_reg(insn);
        guard!(self, dst_reg.is_pointer(), "store to non-pointer register");

        let store_size = match insn.opcode() & LOAD_SIZE_MASK {
            SIZE_DW => 8,
            SIZE_W => 4,
            SIZE_H => 2,
            SIZE_B => 1,
            _ => unreachable!(),
        };

        match dst_reg {
            RegisterState::Uninit => guard!(self, "store to uninit register"),
            RegisterState::PtrToStack { pointer } => {
                let dst = pointer
                    .checked_add_signed(insn.offset() as i32)
                    .ok_or(self.err("store overflows stack"))?;
                guard!(
                    self,
                    dst.is_multiple_of(store_size),
                    "unaligned stack write"
                );
                guard!(
                    self,
                    self.stack_range.contains(&dst)
                        && self.stack_range.contains(&(dst + store_size - 1)),
                    "store outside stack bounds"
                );

                let write_end = dst + store_size;

                let has_overlap = self
                    .stack_objects
                    .range(dst.saturating_sub(7)..write_end)
                    .any(|(&addr, &(len, _))| {
                        let obj_end = addr + len;
                        !(addr == dst && len == store_size)
                            && !(write_end <= addr || dst >= obj_end)
                    });
                guard!(
                    self,
                    !has_overlap,
                    "store partially overlaps existing stack slot"
                );

                let src_state = self
                    .src_reg(insn)
                    .unwrap_or(scalar_reg(ScalarRange::exact(insn.imm() as u64)));

                self.stack_objects.insert(dst, (store_size, src_state));
            }
            RegisterState::PtrToMapValue { map_fd, offset } => {
                let bpf_map = self
                    .vm
                    .map_by_fd(map_fd)
                    .ok_or(self.err("store to unknown map FD"))?;
                let map_val = bpf_map
                    .spec
                    .value
                    .ok_or(self.err("map has no associated value BTF type"))?;
                let offset = offset
                    .checked_add_signed(insn.offset() as i32)
                    .ok_or(self.err("store overflows map value"))?;
                guard!(
                    self,
                    bpf_map
                        .btf
                        .is_offset_valid(map_val, offset, Some(store_size))
                        == Some(true),
                    "store at invalid map value offset"
                );
            }
            _ => guard!(self, "unsupported store target"),
        }

        Ok(())
    }

    fn check_jmp(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let jmp_op = insn.opcode() & JMP_OP_MASK;

        if jmp_op == BPF_CALL {
            return self.check_jmp_call(insn);
        }

        if jmp_op == BPF_EXIT {
            guard!(self, insn.offset() == 0, "reserved offset field");
            guard!(self, insn.src_reg() == 0, "reserved offset field");
            guard!(
                self,
                insn.opcode() & 0b1111 == BPF_JMP | BPF_K,
                "must be BPF_JMP | BPF_K"
            );
            self.exit = true;
            return Ok(());
        }

        let offset = if insn.opcode() == BPF_JMP32 | BPF_K | BPF_JA {
            insn.imm()
        } else {
            insn.offset() as i32
        };
        let target_pc = self.pc + offset as isize;

        guard!(self, offset != -1, "infinite halt");
        guard!(
            self,
            target_pc >= self.starting_pc && target_pc < self.prog.insns.len() as isize,
            "invalid offset"
        );

        if jmp_op == BPF_JA {
            let mut new = VerifierState {
                pc: target_pc,
                indent: self.indent + 1,
                ..self.clone()
            };

            let pad = " ".repeat(self.indent * 4);
            eprintln!("{pad}=== EXECUTING BRANCH -> pc {target_pc}");
            new.run()?;
            eprintln!("{pad}=== BRANCH EXECUTED");

            // TODO: this is an unconditional jump
            // we shouldnt run it in a separate state
            // just override the current PC

            self.exit = true;

            return Ok(());
        }

        let known_val = |val: u64| {
            if insn.class() == BPF_JMP32 {
                ExprVal::Known(ExprRange {
                    min: val as u32 as u64,
                    max: val as u32 as u64,
                    stride: 1,
                })
            } else {
                ExprVal::Known(ExprRange {
                    min: val,
                    max: val,
                    stride: 1,
                })
            }
        };

        let scalar_to_expr = |s: Scalar, class: u8| -> ExprVal {
            let mask = if class == BPF_JMP32 {
                u32::MAX as u64
            } else {
                u64::MAX
            };
            let (min, max, stride) = match s {
                Scalar::U32(r) => (r.min as u64, r.max as u64, r.stride as u64),
                Scalar::U64(r) => (r.min & mask, r.max & mask, r.stride & mask),
                Scalar::Unknown => return ExprVal::Unkown,
            };
            ExprVal::Known(ExprRange { min, max, stride })
        };

        let dst_idx = insn.dst_reg() as usize;
        let mut branch_vm = VerifierState {
            pc: target_pc,
            indent: self.indent + 1,
            ..self.clone()
        };

        let lhs = match self.registers[insn.dst_reg() as usize] {
            RegisterState::Scalar(s) => scalar_to_expr(s, insn.class()),
            RegisterState::PtrToMapValueOrNull { map_fd } => ExprVal::PtrToMapValueOrNull(map_fd),

            // There's no refinement to be done
            RegisterState::PtrToMapValue { .. } => return branch_vm.run(),

            _ => guard!(self, "unsupported dst register for comparison"),
        };

        let rhs = match self.src_reg(insn) {
            Err(_) => known_val(insn.imm() as u32 as u64),
            Ok(RegisterState::Scalar(s)) => scalar_to_expr(s, insn.class()),
            Ok(RegisterState::PtrToMapValueOrNull { map_fd }) => {
                ExprVal::PtrToMapValueOrNull(map_fd)
            }

            // There's no refinement to be done
            Ok(RegisterState::PtrToMapValue { .. }) => return branch_vm.run(),

            Ok(_) => guard!(self, "unsupported src register for comparison"),
        };

        let branch = decide_branch(jmp_op, lhs, rhs);

        let narrow = |reg: RegisterState| -> RegisterState {
            if insn.class() != BPF_JMP32 {
                return reg;
            }
            match reg {
                RegisterState::Scalar(Scalar::U64(r)) => {
                    RegisterState::Scalar(Scalar::U32(ScalarRange {
                        min: r.min as u32,
                        max: r.max as u32,
                        stride: r.stride as u32,
                    }))
                }
                other => other,
            }
        };

        if let Some(branch_reg) = branch.branch_reg {
            branch_vm.registers[dst_idx] = narrow(branch_reg);
        }
        if let Some(fallthrough_reg) = branch.fallthrough_reg {
            self.registers[dst_idx] = narrow(fallthrough_reg);
        }

        match branch.decision {
            BranchDecision::Both => {}
            BranchDecision::SkipFallthrough => self.exit = true,
            BranchDecision::SkipBranch => return Ok(()),
        }

        let pad = " ".repeat(self.indent * 4);
        eprintln!("{pad}=== EXECUTING BRANCH -> pc {target_pc}");
        branch_vm.run()?;
        eprintln!("{pad}=== BRANCH EXECUTED");

        Ok(())
    }

    fn check_jmp_call(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        guard!(
            self,
            insn.opcode() & 0b1111 == BPF_JMP | BPF_K,
            "call must be BPF_JMP | BPF_K"
        );

        match insn.src_reg() {
            BPF_PSEUDO_CALL => guard!(self, "sub-program calls are not supported yet"),
            BPF_HELPER_CALL => {
                let helper_id = insn.imm() as usize;
                (BPF_HELPER_TABLE[helper_id].params)(self.vm, &self.registers, *insn)
                    .map_err(|_| self.err("helper parameter validation failed"))?;

                self.registers[0] =
                    (BPF_HELPER_TABLE[helper_id].retval)(self.vm, &self.registers, *insn);
            }
            _ => {}
        }

        Ok(())
    }
}

type ExprRange = ScalarRange<u64>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExprVal {
    Known(ExprRange),
    Unkown,
    PtrToMapValueOrNull(i32),
}

impl ExprVal {
    fn is_single_val(&self) -> bool {
        match self {
            Self::PtrToMapValueOrNull(_) => true,
            ExprVal::Known(range) => range.min == range.max,
            _ => false,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct BranchResult {
    decision: BranchDecision,
    branch_reg: Option<RegisterState>,
    fallthrough_reg: Option<RegisterState>,
}

impl BranchResult {
    fn skip_branch() -> Self {
        Self {
            decision: BranchDecision::SkipBranch,
            ..Self::default()
        }
    }
    fn skip_fallthrough() -> Self {
        Self {
            decision: BranchDecision::SkipFallthrough,
            ..Self::default()
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
enum BranchDecision {
    #[default]
    Both,
    SkipBranch,
    SkipFallthrough,
}

fn scalar_reg(r: ExprRange) -> RegisterState {
    RegisterState::Scalar(Scalar::U64(r))
}

/// Decides how the branch will be taken and refines the registers.
///
/// * SRC=Unknown: both branches are taken, no refinement done
/// * DST=Unknown, SRC=Known: creates a range for DST and refines using SRC
/// * SRC=DST if they represent a single value:
///   * If JEQ, JGE, JSGE, JLE, JSLE: skip fallthrough
///   * If JNE, JGT, JSGT, JLT, JSLT: skip branch
/// * DST=[`ExprVal::PtrToMapValueOrNull`], SRC=Known:
///   * If JEQ and SRC does not contain NULL: refine to [`RegisterState::PtrToMapValue`] on branch
///   * If JEQ and SRC is NULL: refine to [`RegisterState::PtrToMapValue`] on fallthrough
///   * If JNE and SRC is NULL: refine to [`RegisterState::PtrToMapValue`] on branch
/// * DST=Known, SRC=Known (range-vs-range refinement):
///   * JEQ: skip branch if no overlap. Branch narrows DST to the intersection
///     with SRC. If SRC is a single value, fallthrough excludes it from DST's boundary.
///   * JNE: skip fallthrough if no overlap. Fallthrough narrows DST to the
///     intersection. If SRC is a single value, branch excludes it from DST's boundary.
///   * JGT/JSGT: branch narrows DST.min up to SRC.min+1, fallthrough narrows
///     DST.max down to SRC.max. Skip branch if DST.max <= SRC.min, skip
///     fallthrough if DST.min > SRC.max.
fn decide_branch(op: u8, lhs: ExprVal, rhs: ExprVal) -> BranchResult {
    let (dst, src) = match (lhs, rhs) {
        (_, ExprVal::Unkown) => return BranchResult::default(),

        (ExprVal::Unkown, ExprVal::Known(b)) => (
            ExprRange {
                min: 0,
                max: u32::MAX as u64,
                stride: 1,
            },
            b,
        ),

        (lhs, rhs) if lhs.is_single_val() && lhs == rhs => {
            return match op {
                BPF_JEQ | BPF_JGE | BPF_JSGE | BPF_JLE | BPF_JSLE => {
                    BranchResult::skip_fallthrough()
                }
                BPF_JNE | BPF_JGT | BPF_JSGT | BPF_JLT | BPF_JSLT => BranchResult::skip_branch(),
                BPF_JSET => todo!(),
                _ => BranchResult::default(),
            };
        }

        // TODO: prove for JGE, JLE, JGT, JLT
        (ExprVal::PtrToMapValueOrNull(fd), ExprVal::Known(val)) => {
            let mut result = BranchResult::default();
            let register_state = Some(RegisterState::PtrToMapValue {
                map_fd: fd,
                offset: 0,
            });

            match op {
                BPF_JEQ if val.single_val() == Some(0) => result.fallthrough_reg = register_state,
                BPF_JEQ if !val.contains(0) => result.branch_reg = register_state,
                BPF_JNE if val.single_val() == Some(0) => result.branch_reg = register_state,
                _ => {}
            }

            return result;
        }

        (ExprVal::Known(a), ExprVal::Known(b)) => (a, b),

        (ExprVal::Known(_), ExprVal::PtrToMapValueOrNull(_))
        | (ExprVal::Unkown, ExprVal::PtrToMapValueOrNull(_))
        | (ExprVal::PtrToMapValueOrNull(_), ExprVal::PtrToMapValueOrNull(_)) => todo!(),
    };

    let mut result = BranchResult::default();

    match op {
        BPF_JEQ => {
            if !dst.overlap(&src) {
                return BranchResult::skip_branch();
            }
            // Branch: dst must equal src, so narrow to intersection
            let min = dst.min.max(src.min);
            let max = dst.max.min(src.max);
            let intersection = ExprRange {
                min,
                max,
                stride: if min == max { 1 } else { dst.stride },
            };
            result.branch_reg = Some(scalar_reg(intersection));
            // Fallthrough: dst != src. We can only exclude a boundary
            // point; interior holes can't be represented.
            if let Some(src_val) = src.single_val() {
                match dst.exclude(src_val) {
                    Some(r) => result.fallthrough_reg = Some(scalar_reg(r)),
                    None => result.decision = BranchDecision::SkipFallthrough,
                }
            }
        }
        BPF_JNE => {
            if !dst.overlap(&src) {
                return BranchResult::skip_fallthrough();
            }
            // Fallthrough: dst == src, so narrow to intersection
            let min = dst.min.max(src.min);
            let max = dst.max.min(src.max);
            let intersection = ExprRange {
                min,
                max,
                stride: if min == max { 1 } else { dst.stride },
            };
            result.fallthrough_reg = Some(scalar_reg(intersection));
            // Branch: dst != src. Exclude boundary point if possible.
            if let Some(src_val) = src.single_val() {
                match dst.exclude(src_val) {
                    Some(r) => result.branch_reg = Some(scalar_reg(r)),
                    None => result.decision = BranchDecision::SkipBranch,
                }
            }
        }
        BPF_JGT | BPF_JSGT => {
            // Branch taken when dst > src.
            // dst > src and src >= src.min → dst >= src.min + 1
            let br_min = src.min.checked_add(1).unwrap_or(u64::MAX);
            if br_min > dst.max {
                result.decision = BranchDecision::SkipBranch;
            } else {
                result.branch_reg = Some(scalar_reg(ExprRange {
                    min: br_min.max(dst.min),
                    max: dst.max,
                    stride: dst.stride,
                }));
            }
            // Fallthrough when dst <= src.
            // dst <= src and src <= src.max → dst <= src.max
            if src.max < dst.min {
                result.decision = BranchDecision::SkipFallthrough;
            } else {
                result.fallthrough_reg = Some(scalar_reg(ExprRange {
                    min: dst.min,
                    max: src.max.min(dst.max),
                    stride: dst.stride,
                }));
            }
        }
        _ => {}
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn er(min: u64, max: u64, stride: u64) -> ExprRange {
        ExprRange { min, max, stride }
    }

    #[test]
    fn decide_branch_known_known() {
        use BranchDecision::*;

        let neg1 = -1i32 as u32 as u64;
        let neg5 = -5i32 as u32 as u64;
        let neg10 = -10i32 as u32 as u64;

        let cases: &[(u8, (u64, u64, u64), (u64, u64, u64), BranchDecision)] = &[
            (BPF_JEQ, (1, 1, 1), (1, 1, 1), SkipFallthrough),
            (BPF_JNE, (1, 1, 1), (1, 1, 1), SkipBranch),
            (BPF_JEQ, (0, 64, 4), (0, 64, 4), Both),
            (BPF_JEQ, (0, 32, 2), (32, 64, 4), Both),
            (BPF_JEQ, (0, 31, 2), (32, 64, 4), SkipBranch),
            (BPF_JNE, (0, 31, 2), (32, 64, 4), SkipFallthrough),
            // -1i32 as u32 == -1i32 as u32
            (BPF_JEQ, (neg1, neg1, 1), (neg1, neg1, 1), SkipFallthrough),
            // [-10..-1] vs [-5..-1]: overlapping
            (BPF_JEQ, (neg10, neg1, 1), (neg5, neg1, 1), Both),
            // [0..10] vs [-5..-1]: no overlap (unsigned: 0..10 vs 0xFFFFFFFB..0xFFFFFFFF)
            (BPF_JEQ, (0, 10, 1), (neg5, neg1, 1), SkipBranch),
            (BPF_JNE, (0, 10, 1), (neg5, neg1, 1), SkipFallthrough),
        ];

        for (op, lhs, rhs, expected) in cases {
            let result = decide_branch(
                *op,
                ExprVal::Known(er(lhs.0, lhs.1, lhs.2)),
                ExprVal::Known(er(rhs.0, rhs.1, rhs.2)),
            );
            assert_eq!(result.decision, *expected, "{op:#x} {lhs:?} vs {rhs:?}");
        }
    }

    #[test]
    fn decide_branch_map_null() {
        let non_null = Some(RegisterState::PtrToMapValue {
            map_fd: 0,
            offset: 0,
        });

        let cases: &[(
            u8,
            (u64, u64, u64),
            Option<RegisterState>,
            Option<RegisterState>,
        )] = &[
            // if equal to 0, ptr is null on branch, fallthrough is non-null
            (BPF_JEQ, (0, 0, 1), None, non_null),
            // can't prove it will be non-null on fallthrough, but ptr can't be 0 on branch
            (BPF_JEQ, (1, 5, 1), non_null, None),
            // range including 0, can't prove anything
            (BPF_JEQ, (0, 5, 1), None, None),
            // if not equal to 0, ptr is non-null on branch
            (BPF_JNE, (0, 0, 1), non_null, None),
            // range including 0, can't prove anything
            (BPF_JNE, (0, 5, 1), None, None),
        ];

        for (op, rhs, exp_branch, exp_ft) in cases {
            let result = decide_branch(
                *op,
                ExprVal::PtrToMapValueOrNull(0),
                ExprVal::Known(er(rhs.0, rhs.1, rhs.2)),
            );
            assert_eq!(result.branch_reg, *exp_branch, "{op:#x} {rhs:?} branch_reg");
            assert_eq!(
                result.fallthrough_reg, *exp_ft,
                "{op:#x} {rhs:?} fallthrough_reg"
            );
        }
    }

    #[test]
    fn decide_branch_jeq_refinement() {
        use BranchDecision::*;

        let sr = |min, max, stride| Some(scalar_reg(er(min, max, stride)));

        // range [2..8, stride 2] JEQ 2, branch gets exact 2, fallthrough gets [4..8]
        let r = decide_branch(
            BPF_JEQ,
            ExprVal::Known(er(2, 8, 2)),
            ExprVal::Known(er(2, 2, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(2, 2, 1));
        assert_eq!(r.fallthrough_reg, sr(4, 8, 2));

        // range [2..8, stride 2] JEQ 8, branch gets exact 8, fallthrough gets [2..6]
        let r = decide_branch(
            BPF_JEQ,
            ExprVal::Known(er(2, 8, 2)),
            ExprVal::Known(er(8, 8, 1)),
        );
        assert_eq!(r.branch_reg, sr(8, 8, 1));
        assert_eq!(r.fallthrough_reg, sr(2, 6, 2));

        // range [5..5] JEQ 5, branch always taken
        let r = decide_branch(
            BPF_JEQ,
            ExprVal::Known(er(5, 5, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // range [2..8] JEQ 99, branch never taken
        let r = decide_branch(
            BPF_JEQ,
            ExprVal::Known(er(2, 8, 1)),
            ExprVal::Known(er(99, 99, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        let neg1 = -1i32 as u32 as u64;
        let neg5 = -5i32 as u32 as u64;
        let neg10 = -10i32 as u32 as u64;

        // [-10..-1] JEQ -1: branch exact -1, fallthrough [-10..-2]
        let r = decide_branch(
            BPF_JEQ,
            ExprVal::Known(er(neg10, neg1, 1)),
            ExprVal::Known(er(neg1, neg1, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(neg1, neg1, 1));
        assert_eq!(r.fallthrough_reg, sr(neg10, neg1 - 1, 1));

        // [-10..-1] JEQ -10: branch exact -10, fallthrough [-9..-1]
        let r = decide_branch(
            BPF_JEQ,
            ExprVal::Known(er(neg10, neg1, 1)),
            ExprVal::Known(er(neg10, neg10, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(neg10, neg10, 1));
        assert_eq!(r.fallthrough_reg, sr(neg10 + 1, neg1, 1));

        // [-5..-1] JNE -5: fallthrough exact -5, branch [-4..-1]
        let r = decide_branch(
            BPF_JNE,
            ExprVal::Known(er(neg5, neg1, 1)),
            ExprVal::Known(er(neg5, neg5, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.fallthrough_reg, sr(neg5, neg5, 1));
        assert_eq!(r.branch_reg, sr(neg5 + 1, neg1, 1));
    }

    #[test]
    fn decide_branch_jgt_refinement() {
        use BranchDecision::*;

        let sr = |min, max, stride| Some(scalar_reg(er(min, max, stride)));

        // range [0..10] JGT 5, branch [6..10], fallthrough [0..5]
        let r = decide_branch(
            BPF_JGT,
            ExprVal::Known(er(0, 10, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, 10, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 5, 1));

        // range [0..5] JGT 10, branch impossible
        let r = decide_branch(
            BPF_JGT,
            ExprVal::Known(er(0, 5, 1)),
            ExprVal::Known(er(10, 10, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        // range [10..20] JGT 5, fallthrough impossible
        let r = decide_branch(
            BPF_JGT,
            ExprVal::Known(er(10, 20, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // [0..20] JGT [3..7]: branch min = 3+1=4, fallthrough max = 7
        let r = decide_branch(
            BPF_JGT,
            ExprVal::Known(er(0, 20, 1)),
            ExprVal::Known(er(3, 7, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(4, 20, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 7, 1));

        // [0..5] JGT [5..10]: dst.max(5) <= src.min(5), branch impossible
        let r = decide_branch(
            BPF_JGT,
            ExprVal::Known(er(0, 5, 1)),
            ExprVal::Known(er(5, 10, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        // [10..20] JGT [0..5]: dst.min(10) > src.max(5), fallthrough impossible
        let r = decide_branch(
            BPF_JGT,
            ExprVal::Known(er(10, 20, 1)),
            ExprVal::Known(er(0, 5, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // [0..10] JGT [0..10]: overlapping, both paths possible
        // branch min = 0+1=1, fallthrough max = 10
        let r = decide_branch(
            BPF_JGT,
            ExprVal::Known(er(0, 10, 1)),
            ExprVal::Known(er(0, 10, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(1, 10, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 10, 1));
    }

    #[test]
    fn decide_branch_unknown_refinement() {
        use BranchDecision::*;

        let max = u32::MAX as u64;
        let sr = |min, max, stride| Some(scalar_reg(er(min, max, stride)));

        // Unknown JEQ 0: branch gets exact 0, fallthrough gets [1..MAX]
        let r = decide_branch(BPF_JEQ, ExprVal::Unkown, ExprVal::Known(er(0, 0, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(0, 0, 1));
        assert_eq!(r.fallthrough_reg, sr(1, max, 1));

        // Unknown JEQ 42: branch gets exact 42, fallthrough unchanged (interior)
        let r = decide_branch(BPF_JEQ, ExprVal::Unkown, ExprVal::Known(er(42, 42, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(42, 42, 1));
        assert_eq!(r.fallthrough_reg, sr(0, max, 1));

        // Unknown JNE 0: fallthrough gets exact 0, branch gets [1..MAX]
        let r = decide_branch(BPF_JNE, ExprVal::Unkown, ExprVal::Known(er(0, 0, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.fallthrough_reg, sr(0, 0, 1));
        assert_eq!(r.branch_reg, sr(1, max, 1));

        // Unknown JGT 5: branch gets [6..MAX], fallthrough gets [0..5]
        let r = decide_branch(BPF_JGT, ExprVal::Unkown, ExprVal::Known(er(5, 5, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, max, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 5, 1));
    }
}
