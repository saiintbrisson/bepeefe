use std::{borrow::Cow, collections::BTreeMap, ops::Range, sync::Arc};

use crate::{
    btf::{Btf, BtfKind, BtfTypeId},
    capture::{Capture, Event, VerifierEvent},
    hook::ProgType,
    isa::{alu::*, jmp::*, load::*, *},
    object::EbpfProgram,
    vm::{MAX_CALL_FRAMES, Vm, helpers},
};

#[derive(Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)]
pub enum VerifierError {
    #[error("too many context arguments: {0} > 5")]
    TooManyContextArguments(usize),
    #[error("context argument type not supported: {ty:?}")]
    UnsupportedContextType { arg_id: usize, ty: BtfTypeId },
    #[error(
        "{insn_off}: {} - {}: {msg}",
        crate::isa::insn_name(*insn),
        crate::isa::dump::disasm(*insn, None)
    )]
    Other {
        insn: Insn,
        insn_off: usize,
        msg: &'static str,
        registers: Box<[RegisterState; 11]>,
    },
}

impl VerifierError {
    pub fn report(&self, prog: &EbpfProgram) -> String {
        let VerifierError::Other {
            insn,
            insn_off,
            msg,
            registers,
        } = self
        else {
            return format!("error: {self}\n");
        };

        let btf = &prog.btf;
        let radius = 3;
        let start = insn_off.saturating_sub(radius);
        let end = (insn_off + radius + 1).min(prog.insns.len());
        let pc_width = end.saturating_sub(1).to_string().len().max(2);
        let gutter = " ".repeat(pc_width + 4);

        let mut out = format!("error: {msg}\n  --> pc {insn_off}\n\n");

        let mut prev_line_off: Option<u32> = None;
        for pc in start..end {
            let Some(cur) = prog.insns.get(pc) else {
                break;
            };
            let next = prog.insns.get(pc + 1).copied();
            let dis = crate::isa::dump::disasm(*cur, next);

            let line_entry = (|| {
                let entry = prog.line_info.get(&pc)?;
                let line = btf.string(entry.line_off)?;
                Some((entry.line_off, entry.line_no, line.into_owned()))
            })();
            let annotation = match &line_entry {
                Some((off, _, _)) if prev_line_off == Some(*off) => String::new(),
                Some((_, line_no, line)) => format!("    ; @{line_no:<3}  {}", line.trim()),
                None => String::new(),
            };
            if let Some((off, _, _)) = &line_entry {
                prev_line_off = Some(*off);
            }

            let marker = if pc == *insn_off { '>' } else { ' ' };
            out.push_str(&format!(
                " {marker} {pc:>w$} | {dis}{annotation}\n",
                w = pc_width,
            ));

            if pc == *insn_off {
                let dst = insn.dst_reg();
                let src = insn.src_reg();
                // `dst`/`src` are 4-bit instruction fields (0..=15). The
                // failing instruction may itself have a register index >= 11
                // (that's exactly why `check_insn` would have rejected it),
                // so use `.get` and degrade gracefully.
                let fmt_reg = |idx: u8| match registers.get(idx as usize) {
                    Some(state) => format!("{state:?}"),
                    None => "<invalid register>".to_string(),
                };
                out.push_str(&format!("{gutter}|   r{dst} = {}", fmt_reg(dst)));
                if src != dst {
                    out.push_str(&format!(", r{src} = {}", fmt_reg(src)));
                }
                out.push('\n');
            }
        }
        out
    }
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RegisterState {
    #[default]
    Uninit,
    Scalar(Scalar),
    PtrToCtx {
        /// BTF id of the context struct this pointer addresses. Carried so
        /// that loads/stores can look up per-field rules from
        /// [`VerifierConfig::field_rules`].
        btf_id: BtfTypeId,
        offset: ScalarRange<u32>,
        size: u32,
    },
    /// A pointer into packet data. Produced by a context load whose field
    /// rule yields [`FieldRegKind::PacketData`].
    ///
    /// Cannot be dereferenced until it has been bounds-checked against a
    /// [`PtrToPacketEnd`].
    PtrToPacket {
        /// Pointers sharing an `id` are guaranteed equal at runtime, so a
        /// bounds check on one refines all of them. Adding a known scalar
        /// shifts `offset` while keeping `id`, and adding an unknown scalar
        /// produces a fresh id with offset reset.
        ///
        /// That is to say that all pointers with the same ID refer to the same
        /// value minus their offset. A `ptr(id=1, offset=10)` points to the
        /// same packet section as `ptr(id=1, offset=0)`.
        id: u32,
        offset: ScalarRange<u32>,
    },
    /// Pointer one past the last valid packet byte. Used only as the right
    /// operand of comparisons that refine a [`PtrToPacket`].
    PtrToPacketEnd,
    /// Pointer to packet metadata (`data_meta`). Lives before `data` and
    /// follows the same id/offset mechanism as [`PtrToPacket`].
    PtrToPacketMeta {
        id: u32,
        offset: ScalarRange<u32>,
    },
    PtrToStack {
        offset: ScalarRange<u32>,
    },
    PtrToMap {
        map_fd: u16,
    },
    /// A non-null pointer to a map value, returned by `map_lookup_elem`. Either
    /// returned by an array or refined through a check against NULL.
    PtrToMapValue {
        map_fd: u16,
        offset: ScalarRange<u32>,
    },
    /// Pointer to a map value or NULL. Returned by map_lookup_elem. Arrays
    /// never return null.
    ///
    /// Must be bounds-checked against NULL in order to transform into
    /// a [`RegisterState::PtrToMapValue`].
    PtrToMapValueOrNull {
        map_fd: u16,
    },
}

/// Known scalar representation.
///
/// Scalar values are most frequently not exact. The verifier sees them as
/// ranges. Values that exist from A to B, sometimes stepped. These ranges are
/// _refined_ when performing jumps, adjusted to be wider or narrower.
/// Arithmetic operations can expand or contract them, adds perform offsets in
/// the range (min + VAL, max + VAL), shifts change the _stride_ (interval
/// between numbers in the range, or step).
///
/// The verifier uses this information to validate pointer accesses, predict
/// branch executions, etc.
///
/// Let's illustrate what happens:
/// ```asm
/// 1: u16[] arr = [0..64]
/// 2: r0 = X                ; r0 = Unknown
/// 3: if r0 < 1 goto done   ; r0 = Range { min: 1, max: u32::MAX, stride: 1 }
/// 4: r0 += 1               ; r0 = Range { min: 2, max: u32::MAX + 1, stride: 1 }
///                          ; max wraps here, next line will fix this
/// 5: if r0 >= 64 goto done ; r0 = Range { min: 2, max: 63, stride: 1 }
/// 6: r0 = r0 << 1          ; r0 = Range { min: 4, max: 126, stride: 2 }
/// 7: r1 = arr[r0]          ; verifier guarantees r0.min and r0.max are within
///                          ; ranges, and that r0.stride aligns to real elements
/// 8: done: exit
/// ```
///
/// When accessing an array, the verifier must guarantee the code won't perform
/// an out-of-bounds execution. By gating the code in line 3 and 5, the verifier
/// ensures the access will happen within `arr` bounds. In line 4, we move the
/// next element, range shifts by 1.
///
/// In line 6, the stride comes in to play. Because the array contains u16
/// elements, two bytes in size, the compiler adjusts the pointer by shifting
/// once, and we track this as the register stride. From this point on, we know
/// that no matter what the actual value is, it will always have 2 byte stride.
///
/// The stride is a simple alternative to the Kernel's tnum structure, which
/// tracks what bits can be set. It's not complete and only validates a subset
/// of programs tnum does.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ScalarRange<T: Copy> {
    pub min: T,
    pub max: T,
    pub stride: T,
}

impl<T: Copy + std::fmt::Debug + Eq> std::fmt::Debug for ScalarRange<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.min == self.max {
            f.debug_tuple("ScalarRange").field(&self.min).finish()
        } else {
            f.debug_tuple("ScalarRange")
                .field(&format_args!("{:?}..={:?}", self.min, self.max))
                .field(&self.stride)
                .finish()
        }
    }
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
    /// Add a signed range to this offset range, returning `None` on overflow.
    ///
    /// The resulting stride depends on whether each side is exact (min==max):
    /// - both exact: single point, stride is irrelevant (1).
    /// - self exact, other a range: adding a constant to every element doesn't
    ///   change the spacing, so the other's stride carries through.
    /// - other exact, self a range: same reasoning, self's stride survives.
    /// - both ranges: the combined progression hits multiples of gcd(a, b).
    fn checked_add_signed_range(self, min: i32, max: i32, stride: i32) -> Option<Self> {
        let self_exact = self.min == self.max;
        let other_exact = min == max;
        let stride = match (self_exact, other_exact) {
            (true, true) => 1,
            (true, false) => stride.unsigned_abs(),
            (false, true) => self.stride,
            (false, false) => {
                let (mut a, mut b) = (self.stride, stride.unsigned_abs());
                while b != 0 {
                    (a, b) = (b, a % b);
                }
                a
            }
        };

        Some(ScalarRange {
            min: self.min.checked_add_signed(min)?,
            max: self.max.checked_add_signed(max)?,
            stride: stride.max(1),
        })
    }

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
        let (op, overflow): (fn(_, _) -> _, _) = if shl {
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
        let (op, overflow): (fn(_, _) -> _, _) = if shl {
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

    /// Exclude a boundary value from this range. If `val` equals min, the range
    /// shrinks from below; if it equals max, from above. Interior values don't
    /// change the range (we can't represent a hole). Returns None when the
    /// exclusion empties the range.
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
    pub fn is_pointer(&self) -> bool {
        match self {
            RegisterState::PtrToCtx { .. }
            | RegisterState::PtrToStack { .. }
            | RegisterState::PtrToMap { .. }
            | RegisterState::PtrToMapValue { .. }
            | RegisterState::PtrToMapValueOrNull { .. }
            | RegisterState::PtrToPacket { .. }
            | RegisterState::PtrToPacketEnd
            | RegisterState::PtrToPacketMeta { .. } => true,
            RegisterState::Uninit | RegisterState::Scalar { .. } => false,
        }
    }
}

pub struct VerifierConfig {
    pub max_insns: usize,
    pub max_ctx_params: usize,
    pub allow_unreachable: bool,
    /// Per-field policy for context pointers.
    ///
    /// Allows configuring custom verifier behavior like matching
    /// `__sk_buff.data` to `PTR_TO_PACKET`.
    ///
    /// Keyed by `(container BTF ID, byte offset of the field within the
    /// container)`. For example, `__sk_buff.data` is represented by
    /// `__sk_buff`'s BTF ID and `data`'s byte offset within the struct.
    pub field_rules: BTreeMap<(BtfTypeId, u32), FieldRule>,
    /// Sink for verifier events. Defaults to none, in which case the verifier
    /// emits nothing.
    pub capture: Option<Arc<dyn Capture>>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_insns: u16::MAX as usize,
            max_ctx_params: 1,
            allow_unreachable: false,
            field_rules: BTreeMap::new(),
            capture: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldRule {
    pub access: FieldAccess,
    /// Register state produced by a load from this field when the load size
    /// matches the member size. `None` means always an unknown scalar.
    pub load_reg: Option<FieldRegKind>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldAccess {
    Read,
    Write,
    ReadWrite,
}

impl FieldAccess {
    fn allows_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }
    fn allows_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldRegKind {
    PacketData,
    PacketDataMeta,
    PacketDataEnd,
}

#[derive(Debug, Default, Clone)]
pub struct VerificationOutput {
    pub max_call_depth: usize,
    pub r0: RegisterState,
}

#[derive(Clone)]
pub struct Verifier<'a> {
    vm: &'a Vm,
    prog: Arc<EbpfProgram>,
    config: &'a VerifierConfig,
    registers: [RegisterState; 11],
    starting_pc: isize,
    pc: isize,
    skip: usize,
    exit: bool,

    stack_objects: BTreeMap<u32, (u32, RegisterState)>,
    stack_range: Range<u32>,
    depth: usize,
    call_stack: Vec<usize>,
    max_call_depth: usize,
    expected_return: Option<BtfTypeId>,
    /// Monotonic id assigned to new packet-pointer registers.
    next_pkt_id: u32,
}

impl<'a> Verifier<'a> {
    pub fn new(
        vm: &'a Vm,
        prog: Arc<EbpfProgram>,
        config: &'a VerifierConfig,
    ) -> Result<Self, VerifierError> {
        if prog.func.params_types.len() > 5 {
            return Err(VerifierError::TooManyContextArguments(
                prog.func.params_types.len(),
            ));
        }

        let btf = &prog.btf;
        let registers = Self::registers_from_params(btf, &prog.func.params_types)?;

        let expected_return = prog.func.return_type;

        Ok(Self {
            vm,
            prog,
            config,
            registers,
            starting_pc: 0,
            pc: 0,
            skip: 0,
            exit: false,
            stack_objects: Default::default(),
            stack_range: (0..512),
            depth: 0,
            call_stack: Vec::new(),
            max_call_depth: 0,
            expected_return,
            next_pkt_id: 0,
        })
    }

    /// # Panics
    ///
    /// Panics if `idx` is out of bounds (>= 11).
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "register index is caller-validated to be < 11"
    )]
    fn reg(&self, idx: u8) -> RegisterState {
        self.registers[idx as usize]
    }

    /// # Panics
    ///
    /// Panics if `idx` is out of bounds (>= 11).
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "register index is caller-validated to be < 11"
    )]
    fn set_reg(&mut self, idx: u8, val: RegisterState) {
        self.registers[idx as usize] = val;
    }

    #[inline]
    fn regs(&self) -> &[RegisterState; 11] {
        &self.registers
    }

    fn record(&self, event: VerifierEvent<'_>) {
        if let Some(cap) = self.config.capture.as_ref() {
            cap.record(Event::Verifier(event));
        }
    }

    fn warn(&self, message: impl Into<Cow<'static, str>>) {
        self.record(VerifierEvent::Warning {
            pc: (self.pc - 1).max(0) as usize,
            message: message.into(),
        });
    }

    /// Emits warning events for common pitfalls a developer might make.
    fn hook_advisory(&self, reg: RegisterState, offset: i32, size: u32) {
        let Some(prog_type) = self.prog.hook.as_ref().map(|h| h.prog_type) else {
            return;
        };

        match (prog_type, reg) {
            (ProgType::Tracepoint, RegisterState::PtrToCtx { offset: base, .. })
                if let Some(read_min) = base.min.checked_add_signed(offset) =>
            {
                /// For tracepoint programs, the context's first field is
                /// `struct trace_entry ent`. This struct carries a four
                /// properties regarding that trace execution (type, PID, etc),
                /// but those properties are not what you think they are.
                ///
                /// On tracepoint dispatch however, the Kernel overwrites this
                /// entire struct with a pointer to `pt_regs`, which is needed
                /// by some helpers, e.g. `bpf_perf_event_output`. So the
                /// convetion is to avoid accessing any fields in the first 8
                /// bytes.
                ///
                /// Ref: <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=98b5c2c65c2951772a8fc661f50d675e450e8bce>
                const TRACE_ENTRY_SIZE: u32 = 8;

                if read_min + size <= TRACE_ENTRY_SIZE {
                    self.warn(
                        "reading from trace_entry: kernel overwrites struct with a pointer to pt_regs",
                    );
                }
            }
            _ => {}
        }
    }

    fn registers_from_params(
        btf: &Btf,
        params: &[(String, BtfTypeId)],
    ) -> Result<[RegisterState; 11], VerifierError> {
        let mut registers = [RegisterState::Uninit; 11];

        for (arg_id, ((_, ty), reg)) in params
            .iter()
            .zip(registers.iter_mut().skip(1).take(4))
            .enumerate()
        {
            let btf_type = btf.resolve_must(*ty);

            *reg = match btf_type.kind() {
                BtfKind::Int(_) => RegisterState::Scalar(Scalar::Unknown),
                BtfKind::Ptr(pointee) => {
                    let pointee_ty = btf.resolve_must(*pointee);
                    RegisterState::PtrToCtx {
                        btf_id: pointee_ty.id(),
                        offset: ScalarRange::exact(0),
                        size: pointee_ty.size(),
                    }
                }
                _ => return Err(VerifierError::UnsupportedContextType { arg_id, ty: *ty }),
            };
        }

        registers[10] = RegisterState::PtrToStack {
            offset: ScalarRange::exact(512),
        };

        Ok(registers)
    }

    fn fresh_pkt_id(&mut self) -> u32 {
        let id = self.next_pkt_id;
        self.next_pkt_id += 1;
        id
    }

    /// Fork a sibling verifier that continues from `pc` in the same function
    /// frame. Used for conditional branches and unconditional jumps, the fork
    /// inherits everything from the parent, then gets a fresh walk state.
    fn fork_at(&self, pc: isize) -> Self {
        let mut fork = self.clone();
        fork.pc = pc;
        fork.depth = self.depth + 1;
        fork.skip = 0;
        fork.exit = false;
        fork.max_call_depth = 0;
        fork
    }

    fn run_fork(&mut self, fork: Self) -> Result<(), VerifierError> {
        let out = fork.run()?;
        self.max_call_depth = self.max_call_depth.max(out.max_call_depth);
        Ok(())
    }

    /// Enter a subprogram at `target_pc`. Unlike `fork_at`, this resets
    /// per-frame state (stack, registers, expected return) since a call
    /// establishes a new frame with its own context.
    fn enter_subprog(
        &self,
        target_pc: usize,
        expected_return: Option<BtfTypeId>,
        registers: [RegisterState; 11],
    ) -> Self {
        let mut sub = self.clone();
        sub.registers = registers;
        sub.starting_pc = target_pc as isize;
        sub.pc = target_pc as isize;
        sub.skip = 0;
        sub.exit = false;
        sub.stack_objects.clear();
        sub.stack_range = 0..512;
        sub.depth = self.depth + 1;
        sub.call_stack.push(target_pc);
        sub.max_call_depth = 0;
        sub.expected_return = expected_return;
        sub
    }

    pub fn run(mut self) -> Result<VerificationOutput, VerifierError> {
        let prog = &self.prog.clone();
        let mut iter = prog.insns.iter().enumerate().skip(self.pc as usize);

        while let Some((idx, insn)) = iter.by_ref().nth(self.skip) {
            self.skip = 0;
            self.pc = idx as isize + 1;

            self.check_insn(idx, insn)?;

            if self.exit {
                break;
            }
        }

        guard!(self, self.exit, "program ended without calling exit");

        Ok(VerificationOutput {
            max_call_depth: self.max_call_depth,
            r0: self.reg(0),
        })
    }

    fn check_insn(&mut self, idx: usize, insn: &Insn) -> Result<(), VerifierError> {
        guard!(self, insn.src_reg() <= 10, "insn with invalid src register");
        guard!(
            self,
            insn.dst_reg() < 10 || matches!(insn.class(), BPF_ST | BPF_STX if insn.dst_reg() == 10),
            "insn with invalid dst register"
        );

        match insn.class() {
            BPF_ALU32 | BPF_ALU64 => self.check_alu(insn)?,
            BPF_LD => self.check_non_conventional_ld(insn)?,
            BPF_LDX => self.check_ldx(insn)?,
            BPF_ST | BPF_STX => self.check_st(insn)?,
            BPF_JMP32 | BPF_JMP => {
                if insn.opcode() & JMP_OP_MASK != BPF_EXIT {
                    self.record(VerifierEvent::Insn {
                        depth: self.depth,
                        pc: idx,
                        registers: self.regs(),
                    });
                }

                self.check_jmp(insn)?
            }
            _ => {}
        }

        self.record(VerifierEvent::Insn {
            depth: self.depth,
            pc: idx,
            registers: self.regs(),
        });

        Ok(())
    }

    fn dst_reg(&self, insn: &Insn) -> RegisterState {
        self.reg(insn.dst_reg())
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
        Ok(self.reg(insn.src_reg()))
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "pc - 1 is in 0..insns.len() once any step has succeeded"
    )]
    fn err(&self, msg: &'static str) -> VerifierError {
        let insn_off = self.pc as usize - 1;
        // SAFETY: `pc` only advances within `0..prog.insns.len()` once a successful
        // step has been taken, so `pc - 1` is in range.
        let insn = self.prog.insns[insn_off];

        VerifierError::Other {
            insn,
            insn_off,
            msg,
            registers: Box::new(*self.regs()),
        }
    }

    fn mark_unknown(&mut self, reg: u8) -> Result<(), VerifierError> {
        guard!(self, reg < 10, "tried marking r10 as unknown");
        self.set_reg(reg, RegisterState::Scalar(Scalar::Unknown));
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

        if matches!(
            ptr,
            RegisterState::PtrToPacket { .. } | RegisterState::PtrToPacketMeta { .. }
        ) {
            // Packet pointer ALU operations diverge from the rules for unknown scalars
            return self.check_alu_pkt_ptr(insn, ptr, scalar, op);
        }

        let (scalar_min, scalar_max, scalar_stride) = match scalar {
            Scalar::U32(r) => (r.min as i32, r.max as i32, r.stride as i32),
            // TODO check if upper bits are set, disallow if so.
            Scalar::U64(r) => (r.min as u32 as i32, r.max as u32 as i32, r.stride as i32),
            _ => guard!(self, "pointer arithmetic with unknown scalar"),
        };

        match op {
            BPF_ADD => {
                self.set_reg(
                    insn.dst_reg(),
                    match ptr {
                        RegisterState::PtrToCtx {
                            btf_id,
                            offset,
                            size,
                        } => {
                            let offset = offset
                                .checked_add_signed_range(scalar_min, scalar_max, scalar_stride)
                                .ok_or(self.err("new ptr overflows ctx"))?;
                            guard!(self, size > offset.max, "new ptr overflows ctx");
                            RegisterState::PtrToCtx {
                                btf_id,
                                offset,
                                size,
                            }
                        }
                        RegisterState::PtrToStack { offset } => {
                            let offset = offset
                                .checked_add_signed_range(scalar_min, scalar_max, scalar_stride)
                                .ok_or(self.err("new ptr overflows stack"))?;
                            guard!(
                                self,
                                offset.min >= self.stack_range.start,
                                "new ptr overflows stack"
                            );
                            RegisterState::PtrToStack { offset }
                        }
                        RegisterState::PtrToMapValue { map_fd, offset } => {
                            let offset = offset
                                .checked_add_signed_range(scalar_min, scalar_max, scalar_stride)
                                .ok_or(self.err("new ptr to map value overflows map"))?;
                            RegisterState::PtrToMapValue { map_fd, offset }
                        }
                        _ => guard!(self, "invalid pointer arithmetic operation"),
                    },
                );
            }
            BPF_SUB => {
                let (sub_min, sub_max) = (
                    scalar_max
                        .checked_neg()
                        .ok_or(self.err("ptr sub overflows"))?,
                    scalar_min
                        .checked_neg()
                        .ok_or(self.err("ptr sub overflows"))?,
                );
                self.set_reg(
                    insn.dst_reg(),
                    match ptr {
                        RegisterState::PtrToCtx {
                            btf_id,
                            offset,
                            size,
                        } => {
                            let offset = offset
                                .checked_add_signed_range(sub_min, sub_max, scalar_stride)
                                .ok_or(self.err("new ptr overflows ctx"))?;
                            guard!(self, size > offset.max, "new ptr overflows ctx");
                            RegisterState::PtrToCtx {
                                btf_id,
                                offset,
                                size,
                            }
                        }
                        RegisterState::PtrToMapValue { map_fd, offset } => {
                            let offset = offset
                                .checked_add_signed_range(sub_min, sub_max, scalar_stride)
                                .ok_or(self.err("new ptr to map value overflows map"))?;
                            RegisterState::PtrToMapValue { map_fd, offset }
                        }
                        _ => guard!(self, "invalid pointer arithmetic operation"),
                    },
                );
            }

            _ => guard!(self, "illegal pointer arithmetic operation"),
        }

        Ok(())
    }

    /// Pointer arithmetic on packet pointers (data and meta).
    ///
    /// A packet pointer is a pair `(id, offset)`. The id pins the pointer to a
    /// specific runtime value: any two pointers sharing an id are equal at
    /// runtime, so a bounds check on one refines all of them. The offset tracks
    /// the verifier-known displacement from that anchor.
    ///
    /// Adding or subtracting a single-valued scalar shifts the offset and keeps
    /// the id, the runtime anchor is unchanged. Anything else (an unknown
    /// scalar, or a non-trivial range) generates a fresh id with offset zero,
    /// since the new pointer's runtime value is no longer the same as any
    /// previously checked one.
    fn check_alu_pkt_ptr(
        &mut self,
        insn: &Insn,
        ptr: RegisterState,
        scalar: Scalar,
        op: u8,
    ) -> Result<(), VerifierError> {
        guard!(
            self,
            matches!(op, BPF_ADD | BPF_SUB),
            "illegal pointer arithmetic operation"
        );

        let (id, offset) = match ptr {
            RegisterState::PtrToPacket { id, offset }
            | RegisterState::PtrToPacketMeta { id, offset } => (id, offset),
            _ => return Err(self.err("caller filtered to packet pointers")),
        };

        let single = match scalar {
            Scalar::U32(r) => r.single_val().map(|v| v as i32 as i64),
            Scalar::U64(r) => r.single_val().map(|v| v as i64),
            Scalar::Unknown => None,
        };

        let (new_id, new_offset) = match single {
            Some(v) => {
                let delta = if op == BPF_SUB {
                    v.checked_neg().ok_or(self.err("ptr arith overflows"))?
                } else {
                    v
                };
                let delta =
                    i32::try_from(delta).map_err(|_| self.err("ptr arith does not fit in i32"))?;
                let new_offset = offset
                    .checked_add_signed_range(delta, delta, 1)
                    .ok_or(self.err("new ptr overflows packet offset"))?;
                (id, new_offset)
            }
            None => (self.fresh_pkt_id(), ScalarRange::exact(0)),
        };

        let new_ptr = match ptr {
            RegisterState::PtrToPacket { .. } => RegisterState::PtrToPacket {
                id: new_id,
                offset: new_offset,
            },
            RegisterState::PtrToPacketMeta { .. } => RegisterState::PtrToPacketMeta {
                id: new_id,
                offset: new_offset,
            },
            _ => return Err(self.err("caller filtered to packet pointers")),
        };

        self.set_reg(insn.dst_reg(), new_ptr);
        Ok(())
    }

    /// Checks ALU operations for ADD, SUB, LSH, RSH, ARSH and adjusts the
    /// registers.
    ///
    /// Known scalars are stored as ranges with a min, max, and stride fields.
    /// This function performs adjustments on both ends, min and max, and
    /// adjusts the stride when needed.
    ///
    /// For now, we only adjust if SRC represents a single value, either the
    /// immediate or a scalar with min==max.
    ///
    /// * ADD/SUB keeps the stride if the absolute SRC value is a multiple of
    ///   it, otherwise resets to 1.
    /// * LSH shifts the stride to the left. On overflow, it resets to 1.
    /// * RSH/ARSH shifts the stride to the right. On underflow, it resets to 1.
    ///
    /// If SRC is a range or if an operation fails for any reason, DST is marked
    /// as unknown.
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
                self.set_reg(insn.dst_reg(), RegisterState::Scalar(result));
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
    /// * Moving a pointer simply copies the pointer to DST, only ALU64 can
    ///   perform pointer moves.
    /// * When moving known scalars, the value is trimmed according to the ALU
    ///   class. If the insn is a MOVSX (sign-extension), the offset is checked
    ///   and the known value is sign-extended accordingly.
    /// * Moving unknown scalars simply copy the unknown status.
    /// * Moving IMMs result in known scalars with size according to the class.
    fn check_alu_mov(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        self.set_reg(
            insn.dst_reg(),
            match self.src_reg(insn) {
                Ok(src) if src.is_pointer() => {
                    guard!(self, insn.class() == BPF_ALU64, "partial copy of pointer");
                    guard!(self, insn.offset() == 0, "sign extension on pointer");

                    src
                }
                Ok(RegisterState::Scalar(scalar)) if scalar.is_known() => {
                    let scalar = match (insn.class(), scalar) {
                        (BPF_ALU32, Scalar::U64(r)) => {
                            Scalar::U32(ScalarRange::exact(r.min as u32))
                        }
                        (BPF_ALU64, Scalar::U32(r)) => {
                            Scalar::U64(ScalarRange::exact(r.min as u64))
                        }
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
            },
        );

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
                    _ => return Err(self.err("invalid load size")),
                };

                let src = self.src_reg(insn)?;

                self.hook_advisory(src, insn.offset() as i32, load_size);

                match src {
                    RegisterState::PtrToCtx {
                        btf_id,
                        offset,
                        size,
                    } => {
                        let read_min = offset
                            .min
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("tried reading out of ctx bounds"))?;
                        let read_max = offset
                            .max
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("tried reading out of ctx bounds"))?;
                        let _ = read_min; // underflow caught by checked_add_signed
                        guard!(
                            self,
                            read_max + load_size <= size,
                            "tried reading out of ctx bounds"
                        );

                        // If the host supplied a rule for (container, offset)
                        // and the load size matches the field's member size,
                        // materialize the specialized pointer kind.
                        if offset.single_val().is_some()
                            && let Some(rule) = self
                                .config
                                .field_rules
                                .get(&(btf_id, read_min))
                                .copied()
                                .filter(|r| r.access.allows_read())
                            && let Some(load_reg) = rule.load_reg
                        {
                            let btf = &self.prog.btf;
                            let member_size = btf
                                .get_type_at_offset(btf_id, read_min)
                                .map(|f| f.kind.size(btf));
                            if member_size == Some(load_size) {
                                let dst_state = match load_reg {
                                    FieldRegKind::PacketData => RegisterState::PtrToPacket {
                                        id: 0,
                                        offset: ScalarRange::exact(0),
                                    },
                                    FieldRegKind::PacketDataMeta => {
                                        RegisterState::PtrToPacketMeta {
                                            id: 0,
                                            offset: ScalarRange::exact(0),
                                        }
                                    }
                                    FieldRegKind::PacketDataEnd => RegisterState::PtrToPacketEnd,
                                };
                                self.set_reg(insn.dst_reg(), dst_state);
                                return Ok(());
                            }
                        }
                    }
                    RegisterState::PtrToStack { offset } => {
                        guard!(
                            self,
                            offset.single_val().is_some(),
                            "stack access requires exact pointer offset"
                        );
                        let dst = offset
                            .min
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
                        self.set_reg(insn.dst_reg(), saved_state);
                        return Ok(());
                    }
                    RegisterState::PtrToMap { map_fd: _ } => {
                        return Err(self.err("load through PtrToMap is not supported"));
                    }
                    RegisterState::PtrToMapValue { map_fd, offset } => {
                        let bpf_map = self.vm.get_map(map_fd);
                        let map_val = bpf_map
                            .spec
                            .value
                            .ok_or(self.err("map has no associated value BTF type"))?;
                        let read_min = offset
                            .min
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("load overflows map value"))?;
                        let read_max = offset
                            .max
                            .checked_add_signed(insn.offset() as i32)
                            .ok_or(self.err("load overflows map value"))?;
                        guard!(
                            self,
                            bpf_map.btf.is_access_valid(map_val, read_min, load_size),
                            "tried reading from ptr to map value with invalid offset"
                        );
                        guard!(
                            self,
                            bpf_map.btf.is_access_valid(map_val, read_max, load_size),
                            "tried reading from ptr to map value with invalid offset"
                        );
                    }
                    _ => guard!(self, "invalid memory location"),
                }

                self.mark_unknown(insn.dst_reg())
            }
            MODE_MEMSX => guard!(self, "sign-extension loads are not supported yet"),
            _ => guard!(self, "unsupported load mode"),
        }
    }

    /// Checks for LD IMM64 instructions. For now, only IMM and MAP FD loads
    /// are supported. Signals for the verifier to skip next instruction.
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

        let next = self
            .prog
            .insns
            .get(self.pc as usize)
            .ok_or_else(|| self.err("ld_imm64 expects one more word"))?;

        match insn.src_reg() {
            0 => {
                let imm64 =
                    (insn.imm() as u64 & 0xFFFF_FFFF) | ((next.imm() as u64 & 0xFFFF_FFFF) << 32);
                self.set_reg(
                    insn.dst_reg(),
                    RegisterState::Scalar(Scalar::U64(ScalarRange::exact(imm64))),
                );
            }
            BPF_PSEUDO_MAP_FD => {
                guard!(
                    self,
                    insn.imm() >> u16::BITS == 0,
                    "map fd is larger than allowed"
                );
                let map_fd = insn.imm() as u16;
                guard!(
                    self,
                    self.vm.has_map(map_fd),
                    "referenced non-existing map FD"
                );
                self.set_reg(insn.dst_reg(), RegisterState::PtrToMap { map_fd })
            }
            BPF_PSEUDO_MAP_VALUE => {
                let offset = next.imm() as u32;
                guard!(
                    self,
                    insn.imm() >> u16::BITS == 0,
                    "map fd is larger than allowed"
                );
                let map_fd = insn.imm() as u16;
                guard!(
                    self,
                    self.vm.has_map(map_fd),
                    "referenced non-existing map FD"
                );
                self.set_reg(
                    insn.dst_reg(),
                    RegisterState::PtrToMapValue {
                        map_fd,
                        offset: ScalarRange::exact(offset),
                    },
                );
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
            _ => return Err(self.err("invalid store size")),
        };

        match dst_reg {
            RegisterState::Uninit => guard!(self, "store to uninit register"),
            RegisterState::PtrToStack { offset } => {
                guard!(
                    self,
                    offset.single_val().is_some(),
                    "stack access requires exact pointer offset"
                );
                let dst = offset
                    .min
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

                let src_state = self
                    .src_reg(insn)
                    .unwrap_or(scalar_reg(ScalarRange::exact(insn.imm() as u64)));

                let overlapping: Vec<u32> = self
                    .stack_objects
                    .range(dst.saturating_sub(7)..write_end)
                    .filter_map(|(&addr, &(len, _))| {
                        let obj_end = addr + len;
                        let exact_match = addr == dst && len == store_size;
                        let disjoint = write_end <= addr || dst >= obj_end;
                        (!exact_match && !disjoint).then_some(addr)
                    })
                    .collect();

                if !overlapping.is_empty() {
                    if src_state.is_pointer() {
                        guard!(self, "pointer store partially overlaps existing stack slot");
                    }

                    for &addr in &overlapping {
                        let (_, existing) = self
                            .stack_objects
                            .get(&addr)
                            .ok_or_else(|| self.err("overlapping stack addr is out of bounds"))?;
                        guard!(
                            self,
                            !existing.is_pointer(),
                            "scalar store clobbers pointer on stack"
                        );
                        self.stack_objects.remove(&addr);
                    }
                }

                self.stack_objects.insert(dst, (store_size, src_state));
            }
            RegisterState::PtrToMapValue { map_fd, offset } => {
                let bpf_map = self.vm.get_map(map_fd);
                let map_val = bpf_map
                    .spec
                    .value
                    .ok_or(self.err("map has no associated value BTF type"))?;
                let write_min = offset
                    .min
                    .checked_add_signed(insn.offset() as i32)
                    .ok_or(self.err("store overflows map value"))?;
                let write_max = offset
                    .max
                    .checked_add_signed(insn.offset() as i32)
                    .ok_or(self.err("store overflows map value"))?;
                guard!(
                    self,
                    bpf_map.btf.is_access_valid(map_val, write_min, store_size),
                    "store at invalid map value offset"
                );
                guard!(
                    self,
                    bpf_map.btf.is_access_valid(map_val, write_max, store_size),
                    "store at invalid map value offset"
                );
            }
            RegisterState::PtrToCtx {
                btf_id,
                offset,
                size,
            } => {
                guard!(
                    self,
                    offset.single_val().is_some(),
                    "ctx store requires exact pointer offset"
                );
                let access_off = offset
                    .min
                    .checked_add_signed(insn.offset() as i32)
                    .ok_or(self.err("store overflows ctx"))?;
                guard!(self, access_off + store_size <= size, "store overflows ctx");

                let rule = self
                    .config
                    .field_rules
                    .get(&(btf_id, access_off))
                    .copied()
                    .ok_or(self.err("ctx store to field without a verifier rule"))?;
                guard!(self, rule.access.allows_write(), "ctx store not permitted");

                let btf = &self.prog.btf;
                let member_size = btf
                    .get_type_at_offset(btf_id, access_off)
                    .map(|f| f.kind.size(btf))
                    .ok_or(self.err("ctx store target has no resolvable BTF size"))?;
                guard!(
                    self,
                    member_size == store_size,
                    "ctx store size does not match member size"
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

            if matches!(self.reg(0), RegisterState::PtrToStack { .. }) {
                return Err(self.err("cannot return a pointer to the stack"));
            }

            if let Some(ty) = self.expected_return {
                let btf_type = self.prog.btf.resolve_must(ty);
                let ok = match btf_type.kind() {
                    BtfKind::Int(_) => matches!(self.reg(0), RegisterState::Scalar(_)),
                    BtfKind::Ptr(_) => self.reg(0).is_pointer(),
                    _ => true,
                };
                if !ok {
                    return Err(self.err("return value does not match declared return type"));
                }
            }

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
            self.record(VerifierEvent::BranchEnter {
                depth: self.depth,
                target_pc: target_pc as usize,
            });
            self.run_fork(self.fork_at(target_pc))?;
            self.record(VerifierEvent::BranchExit { depth: self.depth });

            // TODO: this is an unconditional jump we shouldnt run it in a separate state
            // just override the current PC

            self.exit = true;

            return Ok(());
        }

        let signed = matches!(jmp_op, BPF_JSGT | BPF_JSGE | BPF_JSLT | BPF_JSLE);

        let known_val = |val: u64| {
            let val = if insn.class() == BPF_JMP32 {
                if signed {
                    val as u32 as i32 as i64 as u64
                } else {
                    val as u32 as u64
                }
            } else {
                val
            };
            ExprVal::Known(ExprRange {
                min: val,
                max: val,
                stride: 1,
            })
        };

        let scalar_to_expr = |s: Scalar, class: u8| -> ExprVal {
            let jmp32 = class == BPF_JMP32;
            let mask = if jmp32 { u32::MAX as u64 } else { u64::MAX };
            let (min, max, stride) = match s {
                Scalar::U32(r) => (r.min as u64, r.max as u64, r.stride as u64),
                Scalar::U64(r) => (r.min & mask, r.max & mask, r.stride & mask),
                Scalar::Unknown => return ExprVal::Unkown,
            };
            if signed {
                let (smin, smax) = if jmp32 {
                    (
                        min as u32 as i32 as i64 as u64,
                        max as u32 as i32 as i64 as u64,
                    )
                } else {
                    (min, max)
                };
                if smin as i64 > smax as i64 {
                    return ExprVal::Unkown;
                }
                ExprVal::Known(ExprRange {
                    min: smin,
                    max: smax,
                    stride,
                })
            } else {
                ExprVal::Known(ExprRange { min, max, stride })
            }
        };

        let dst_idx = insn.dst_reg();
        let mut branch_vm = self.fork_at(target_pc);

        let lhs = match self.dst_reg(insn) {
            RegisterState::Scalar(s) => scalar_to_expr(s, insn.class()),
            RegisterState::PtrToMapValueOrNull { map_fd } => ExprVal::PtrToMapValueOrNull(map_fd),

            // There's no refinement to be done
            RegisterState::PtrToMapValue { .. } => return self.run_fork(branch_vm),

            _ => guard!(self, "unsupported dst register for comparison"),
        };

        let rhs = match self.src_reg(insn) {
            Err(_) => known_val(insn.imm() as u32 as u64),
            Ok(RegisterState::Scalar(s)) => scalar_to_expr(s, insn.class()),
            Ok(RegisterState::PtrToMapValueOrNull { map_fd }) => {
                ExprVal::PtrToMapValueOrNull(map_fd)
            }

            // There's no refinement to be done
            Ok(RegisterState::PtrToMapValue { .. }) => return self.run_fork(branch_vm),

            Ok(_) => guard!(self, "unsupported src register for comparison"),
        };

        let branch = decide_branch(jmp_op, lhs, rhs, insn.class() == BPF_JMP32)
            .map_err(|msg| self.err(msg))?;

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
            branch_vm.set_reg(dst_idx, narrow(branch_reg));
        }
        if let Some(fallthrough_reg) = branch.fallthrough_reg {
            self.set_reg(dst_idx, narrow(fallthrough_reg));
        }

        match branch.decision {
            BranchDecision::Both => {}
            BranchDecision::SkipFallthrough => self.exit = true,
            BranchDecision::SkipBranch => return Ok(()),
        }

        self.record(VerifierEvent::BranchEnter {
            depth: self.depth,
            target_pc: target_pc as usize,
        });
        self.run_fork(branch_vm)?;
        self.record(VerifierEvent::BranchExit { depth: self.depth });

        Ok(())
    }

    fn check_jmp_call(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        guard!(
            self,
            insn.opcode() & 0b1111 == BPF_JMP | BPF_K,
            "call must be BPF_JMP | BPF_K"
        );

        match insn.src_reg() {
            BPF_PSEUDO_CALL => self.check_pseudo_call(insn)?,
            BPF_HELPER_CALL => {
                let helper = helpers::lookup(insn.imm())
                    .ok_or_else(|| self.err("BPF_HELPER_CALL refers to invalid helper ID"))?;
                helper
                    .params(self.vm, self.regs(), *insn)
                    .map_err(|_| self.err("helper parameter validation failed"))?;

                let retval = helper
                    .retval(self.vm, self.regs(), *insn)
                    .map_err(|msg| self.err(msg))?;
                self.set_reg(0, retval);
            }
            _ => {}
        }

        Ok(())
    }

    fn check_pseudo_call(&mut self, insn: &Insn) -> Result<(), VerifierError> {
        let target_pc = (self.pc + insn.imm() as isize) as usize;
        let callee_sig = self
            .prog
            .subprogs
            .get(&target_pc)
            .cloned()
            .ok_or_else(|| self.err("call target not aligned to a BTF-described subprogram"))?;

        guard!(
            self,
            self.call_stack.contains(&target_pc),
            "recursive subprogram call"
        );

        guard!(
            self,
            self.call_stack.len() + 1 >= MAX_CALL_FRAMES,
            "subprogram call depth exceeds maximum"
        );

        let btf = &self.prog.btf;
        let callee_registers = Self::registers_from_params(btf, &callee_sig.params_types)
            .map_err(|_| self.err("callee has unsupported parameter type"))?;

        for (expected, actual) in callee_registers.iter().zip(self.regs()) {
            let compatible = matches!(
                (actual, expected),
                (RegisterState::Scalar(_), RegisterState::Scalar(_))
                    | (
                        RegisterState::PtrToCtx { .. },
                        RegisterState::PtrToCtx { .. }
                    )
                    | (
                        RegisterState::PtrToStack { .. }
                            | RegisterState::PtrToMapValue { .. }
                            | RegisterState::PtrToMap { .. },
                        RegisterState::PtrToCtx { .. },
                    )
            );

            if !compatible {
                return Err(self.err("argument type mismatch at subprogram call"));
            }
        }

        let sub = self.enter_subprog(target_pc, callee_sig.return_type, callee_registers);
        let sub_out = sub.run()?;
        self.max_call_depth = self.max_call_depth.max(sub_out.max_call_depth + 1);
        self.set_reg(0, sub_out.r0);

        // R1..R5 are cleared on return
        for i in 1..=5 {
            self.set_reg(i, RegisterState::Uninit);
        }

        Ok(())
    }
}

type ExprRange = ScalarRange<u64>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExprVal {
    Known(ExprRange),
    Unkown,
    PtrToMapValueOrNull(u16),
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
///   * If JEQ and SRC does not contain NULL: refine to
///     [`RegisterState::PtrToMapValue`] on branch
///   * If JEQ and SRC is NULL: refine to [`RegisterState::PtrToMapValue`] on
///     fallthrough
///   * If JNE and SRC is NULL: refine to [`RegisterState::PtrToMapValue`] on
///     branch
/// * DST=Known, SRC=Known (range-vs-range refinement):
///   * JEQ: skip branch if no overlap. Branch narrows DST to the intersection
///     with SRC. If SRC is a single value, fallthrough excludes it from DST's
///     boundary.
///   * JNE: skip fallthrough if no overlap. Fallthrough narrows DST to the
///     intersection. If SRC is a single value, branch excludes it from DST's
///     boundary.
///   * JGT: branch narrows DST.min up to SRC.min+1, fallthrough narrows DST.max
///     down to SRC.max. Skip branch if DST.max <= SRC.min, skip fallthrough if
///     DST.min > SRC.max. Unsigned comparison.
///   * JSGT: same logic but using signed (i64) arithmetic. When the resulting
///     range can't be stored as a valid unsigned range (min > max), we skip the
///     refinement for that path.
fn decide_branch(
    op: u8,
    lhs: ExprVal,
    rhs: ExprVal,
    jmp32: bool,
) -> Result<BranchResult, &'static str> {
    let signed = matches!(op, BPF_JSGT | BPF_JSGE | BPF_JSLT | BPF_JSLE);

    let (dst, src) = match (lhs, rhs) {
        (_, ExprVal::Unkown) => return Ok(BranchResult::default()),

        (ExprVal::Unkown, ExprVal::Known(b)) => {
            let range = match (signed, jmp32) {
                (false, true) => ExprRange {
                    min: 0,
                    max: u32::MAX as u64,
                    stride: 1,
                },
                (false, false) => ExprRange {
                    min: 0,
                    max: u64::MAX,
                    stride: 1,
                },
                (true, true) => ExprRange {
                    min: i32::MIN as i64 as u64,
                    max: i32::MAX as i64 as u64,
                    stride: 1,
                },
                (true, false) => ExprRange {
                    min: i64::MIN as u64,
                    max: i64::MAX as u64,
                    stride: 1,
                },
            };
            (range, b)
        }

        (lhs, rhs) if lhs.is_single_val() && lhs == rhs => {
            return Ok(match op {
                BPF_JEQ | BPF_JGE | BPF_JSGE | BPF_JLE | BPF_JSLE => {
                    BranchResult::skip_fallthrough()
                }
                BPF_JNE | BPF_JGT | BPF_JSGT | BPF_JLT | BPF_JSLT => BranchResult::skip_branch(),
                BPF_JSET => return Err("BPF_JSET refinement is not supported"),
                _ => BranchResult::default(),
            });
        }

        // TODO: prove for JGE, JLE, JGT, JLT
        (ExprVal::PtrToMapValueOrNull(fd), ExprVal::Known(val)) => {
            let mut result = BranchResult::default();
            let register_state = Some(RegisterState::PtrToMapValue {
                map_fd: fd,
                offset: ScalarRange::exact(0),
            });

            match op {
                BPF_JEQ if val.single_val() == Some(0) => result.fallthrough_reg = register_state,
                BPF_JEQ if !val.contains(0) => result.branch_reg = register_state,
                BPF_JNE if val.single_val() == Some(0) => result.branch_reg = register_state,
                _ => {}
            }

            return Ok(result);
        }

        (ExprVal::Known(a), ExprVal::Known(b)) => (a, b),

        (ExprVal::Known(_), ExprVal::PtrToMapValueOrNull(_))
        | (ExprVal::Unkown, ExprVal::PtrToMapValueOrNull(_))
        | (ExprVal::PtrToMapValueOrNull(_), ExprVal::PtrToMapValueOrNull(_)) => {
            return Err("comparison against PtrToMapValueOrNull on this side is not supported");
        }
    };

    let mut result = BranchResult::default();

    match op {
        BPF_JEQ => {
            if !dst.overlap(&src) {
                return Ok(BranchResult::skip_branch());
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
                return Ok(BranchResult::skip_fallthrough());
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
        BPF_JGT => {
            if src.min >= dst.max {
                result.decision = BranchDecision::SkipBranch;
            } else {
                result.branch_reg = Some(scalar_reg(ExprRange {
                    min: (src.min + 1).max(dst.min),
                    max: dst.max,
                    stride: dst.stride,
                }));
            }

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
        BPF_JSGT => {
            let dst_smin = dst.min as i64;
            let dst_smax = dst.max as i64;
            let src_smin = src.min as i64;
            let src_smax = src.max as i64;

            if src_smin >= dst_smax {
                result.decision = BranchDecision::SkipBranch;
            } else {
                let smin = (src_smin + 1).max(dst_smin);
                let smax = dst_smax;
                if smin <= smax {
                    result.branch_reg = Some(scalar_reg(ExprRange {
                        min: smin as u64,
                        max: smax as u64,
                        stride: dst.stride,
                    }));
                }
            }

            if src_smax < dst_smin {
                result.decision = BranchDecision::SkipFallthrough;
            } else {
                let smin = dst_smin;
                let smax = src_smax.min(dst_smax);
                if smin <= smax {
                    result.fallthrough_reg = Some(scalar_reg(ExprRange {
                        min: smin as u64,
                        max: smax as u64,
                        stride: dst.stride,
                    }));
                }
            }
        }
        _ => {}
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn er(min: u64, max: u64, stride: u64) -> ExprRange {
        ExprRange { min, max, stride }
    }

    fn db32(op: u8, lhs: ExprVal, rhs: ExprVal) -> BranchResult {
        decide_branch(op, lhs, rhs, true).expect("decide_branch unsupported case in test")
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
            let result = db32(
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
            offset: ScalarRange::exact(0),
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
            let result = db32(
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
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(2, 8, 2)),
            ExprVal::Known(er(2, 2, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(2, 2, 1));
        assert_eq!(r.fallthrough_reg, sr(4, 8, 2));

        // range [2..8, stride 2] JEQ 8, branch gets exact 8, fallthrough gets [2..6]
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(2, 8, 2)),
            ExprVal::Known(er(8, 8, 1)),
        );
        assert_eq!(r.branch_reg, sr(8, 8, 1));
        assert_eq!(r.fallthrough_reg, sr(2, 6, 2));

        // range [5..5] JEQ 5, branch always taken
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(5, 5, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // range [2..8] JEQ 99, branch never taken
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(2, 8, 1)),
            ExprVal::Known(er(99, 99, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        let neg1 = -1i32 as u32 as u64;
        let neg5 = -5i32 as u32 as u64;
        let neg10 = -10i32 as u32 as u64;

        // [-10..-1] JEQ -1: branch exact -1, fallthrough [-10..-2]
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(neg10, neg1, 1)),
            ExprVal::Known(er(neg1, neg1, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(neg1, neg1, 1));
        assert_eq!(r.fallthrough_reg, sr(neg10, neg1 - 1, 1));

        // [-10..-1] JEQ -10: branch exact -10, fallthrough [-9..-1]
        let r = db32(
            BPF_JEQ,
            ExprVal::Known(er(neg10, neg1, 1)),
            ExprVal::Known(er(neg10, neg10, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(neg10, neg10, 1));
        assert_eq!(r.fallthrough_reg, sr(neg10 + 1, neg1, 1));

        // [-5..-1] JNE -5: fallthrough exact -5, branch [-4..-1]
        let r = db32(
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
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(0, 10, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, 10, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 5, 1));

        // range [0..5] JGT 10, branch impossible
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(0, 5, 1)),
            ExprVal::Known(er(10, 10, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        // range [10..20] JGT 5, fallthrough impossible
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(10, 20, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // [0..20] JGT [3..7]: branch min = 3+1=4, fallthrough max = 7
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(0, 20, 1)),
            ExprVal::Known(er(3, 7, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(4, 20, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 7, 1));

        // [0..5] JGT [5..10]: dst.max(5) <= src.min(5), branch impossible
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(0, 5, 1)),
            ExprVal::Known(er(5, 10, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        // [10..20] JGT [0..5]: dst.min(10) > src.max(5), fallthrough impossible
        let r = db32(
            BPF_JGT,
            ExprVal::Known(er(10, 20, 1)),
            ExprVal::Known(er(0, 5, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // [0..10] JGT [0..10]: overlapping, both paths possible
        // branch min = 0+1=1, fallthrough max = 10
        let r = db32(
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
        let r = db32(BPF_JEQ, ExprVal::Unkown, ExprVal::Known(er(0, 0, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(0, 0, 1));
        assert_eq!(r.fallthrough_reg, sr(1, max, 1));

        // Unknown JEQ 42: branch gets exact 42, fallthrough unchanged (interior)
        let r = db32(BPF_JEQ, ExprVal::Unkown, ExprVal::Known(er(42, 42, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(42, 42, 1));
        assert_eq!(r.fallthrough_reg, sr(0, max, 1));

        // Unknown JNE 0: fallthrough gets exact 0, branch gets [1..MAX]
        let r = db32(BPF_JNE, ExprVal::Unkown, ExprVal::Known(er(0, 0, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.fallthrough_reg, sr(0, 0, 1));
        assert_eq!(r.branch_reg, sr(1, max, 1));

        // Unknown JGT 5: branch gets [6..MAX], fallthrough gets [0..5]
        let r = db32(BPF_JGT, ExprVal::Unkown, ExprVal::Known(er(5, 5, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, max, 1));
        assert_eq!(r.fallthrough_reg, sr(0, 5, 1));

        // Unknown JSGT 5: signed, so unknown is [i32::MIN..i32::MAX]
        // branch gets [6..i32::MAX], fallthrough gets [i32::MIN..5]
        let smin = i32::MIN as i64 as u64;
        let smax = i32::MAX as i64 as u64;
        let r = db32(BPF_JSGT, ExprVal::Unkown, ExprVal::Known(er(5, 5, 1)));
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, smax, 1));
        assert_eq!(r.fallthrough_reg, sr(smin, 5, 1));
    }

    #[test]
    fn decide_branch_jsgt_refinement() {
        use BranchDecision::*;

        let sr = |min, max, stride| Some(scalar_reg(er(min, max, stride)));
        let s = |v: i32| v as i64 as u64;

        // [-10..10] JSGT 5: branch [6..10], fallthrough [-10..5]
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(s(-10), 10, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(6, 10, 1));
        assert_eq!(r.fallthrough_reg, sr(s(-10), 5, 1));

        // [-10..-1] JSGT -5: branch [-4..-1], fallthrough [-10..-5]
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(s(-10), s(-1), 1)),
            ExprVal::Known(er(s(-5), s(-5), 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(s(-4), s(-1), 1));
        assert_eq!(r.fallthrough_reg, sr(s(-10), s(-5), 1));

        // [-5..-1] JSGT 0: all negative < 0, branch impossible
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(s(-5), s(-1), 1)),
            ExprVal::Known(er(0, 0, 1)),
        );
        assert_eq!(r.decision, SkipBranch);

        // [5..10] JSGT 0: all > 0, fallthrough impossible
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(5, 10, 1)),
            ExprVal::Known(er(0, 0, 1)),
        );
        assert_eq!(r.decision, SkipFallthrough);

        // [-10..10] JSGT [-5..5]: range vs range
        // branch min = -5+1 = -4, clamped to dst_min(-10) -> -4; max = 10
        // fallthrough min = -10; max = min(5, 10) = 5
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(s(-10), 10, 1)),
            ExprVal::Known(er(s(-5), 5, 1)),
        );
        assert_eq!(r.decision, Both);
        assert_eq!(r.branch_reg, sr(s(-4), 10, 1));
        assert_eq!(r.fallthrough_reg, sr(s(-10), 5, 1));

        // [5..5] JSGT [5..5]: equal, signed gt is strict, branch impossible
        let r = db32(
            BPF_JSGT,
            ExprVal::Known(er(5, 5, 1)),
            ExprVal::Known(er(5, 5, 1)),
        );
        assert_eq!(r.decision, SkipBranch);
    }
}
