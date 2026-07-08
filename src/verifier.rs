mod branch;
mod event;
#[cfg(test)]
mod tests;

use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::BTreeMap,
    ops::Range,
    sync::Arc,
};

use branch::{ExprRange, ExprVal, decide_branch, scalar_reg};

use crate::{
    btf::{Btf, BtfKind, BtfTypeId},
    capture::{Capture, Event},
    hook::ProgType,
    isa::{alu::*, jmp::*, load::*, *},
    object::EbpfProgram,
    verifier::branch::BranchResult,
    vm::{MAX_CALL_FRAMES, STACK_SIZE, Vm, helpers},
};

pub use {branch::BranchDecision, event::VerifierEvent, walk::PruneSite};

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

mod checks;
mod walk;
use walk::{StateSnapshot, Walk};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub enum RegisterState {
    #[default]
    Uninit,
    Scalar(Scalar),
    PtrToCtx {
        /// BTF id of the context struct this pointer addresses.
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
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
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
            Self::PtrToCtx { .. }
            | Self::PtrToStack { .. }
            | Self::PtrToMap { .. }
            | Self::PtrToMapValue { .. }
            | Self::PtrToMapValueOrNull { .. }
            | Self::PtrToPacket { .. }
            | Self::PtrToPacketEnd
            | Self::PtrToPacketMeta { .. } => true,
            Self::Uninit | Self::Scalar { .. } => false,
        }
    }

    pub fn is_scalar(&self) -> bool {
        matches!(self, Self::Scalar(_))
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

bitflags::bitflags! {
    /// Set of eBPF registers, one bit per register r0 to r10.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct RegMask: u16 {
        const R0 = 1 << 0;
        const R1 = 1 << 1;
        const R2 = 1 << 2;
        const R3 = 1 << 3;
        const R4 = 1 << 4;
        const R5 = 1 << 5;
        const R6 = 1 << 6;
        const R7 = 1 << 7;
        const R8 = 1 << 8;
        const R9 = 1 << 9;
        const R10 = 1 << 10;
    }
}

impl RegMask {
    /// Mask with only register `idx` set. Out-of-range indices produce an
    /// empty mask.
    pub fn single(idx: u8) -> Self {
        Self::from_bits_truncate(1u16.checked_shl(idx as u32).unwrap_or(0))
    }
}

/// Serializes as the list of set register indices, so `r1 | r2` becomes
/// `[1, 2]`, in line with the register arrays used elsewhere in the stream.
impl serde::Serialize for RegMask {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter().map(|flag| flag.bits().trailing_zeros() as u8))
    }
}

/// Inverse of the index-list [`serde::Serialize`] impl, only needed by tests
/// that round-trip events through their wire format.
#[cfg(test)]
impl<'de> serde::Deserialize<'de> for RegMask {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let indices = Vec::<u8>::deserialize(deserializer)?;
        Ok(indices
            .into_iter()
            .fold(RegMask::empty(), |mask, idx| mask | RegMask::single(idx)))
    }
}

/// A written stack slot.
///
/// The size and verifier state stored there, plus the pc of the store that
/// wrote it. Written and read by the store/load checks.
#[derive(Clone, Copy, PartialEq, Eq)]
struct StackSlot {
    size: u32,
    state: RegisterState,
    pc: usize,
}

impl StackSlot {
    /// Whether a store of `store_size` bytes at `dst` partially overwrites this
    /// slot sitting at `addr`, meaning the two byte ranges intersect but the
    /// store does not exactly replace the slot.
    ///
    /// An exact replacement overwrites cleanly and a disjoint store leaves the
    /// slot alone, only a partial overlap has to clear the stale slot.
    fn partially_overwritten_by(&self, addr: u32, dst: u32, store_size: u32) -> bool {
        let obj_end = addr + self.size;
        let write_end = dst + store_size;
        let exact = addr == dst && self.size == store_size;
        let disjoint = write_end <= addr || dst >= obj_end;
        !exact && !disjoint
    }
}

/// A function frame state. Registers, stack, the frame's control (its entry pc,
/// the call stack below it, its return type).
#[derive(Clone)]
struct Frame {
    registers: [RegisterState; 11],
    stack_objects: BTreeMap<u32, StackSlot>,
    /// First pc of this frame, the floor for jump targets.
    starting_pc: usize,
    /// Subprogram entry pcs on the call stack, for the recursion and depth
    /// checks. Its length is this frame's subprogram nesting depth.
    call_stack: Vec<usize>,
    expected_return: Option<BtfTypeId>,
}

impl Frame {
    /// The entry frame.
    fn root(registers: [RegisterState; 11], expected_return: Option<BtfTypeId>) -> Self {
        Frame {
            registers,
            stack_objects: BTreeMap::new(),
            starting_pc: 0,
            call_stack: Vec::new(),
            expected_return,
        }
    }

    /// A callee frame entered at `target`. Fresh registers and stack, its own
    /// `starting_pc`, and the caller's `call_stack` with `target` pushed.
    fn enter(
        registers: [RegisterState; 11],
        target: usize,
        parent_call_stack: &[usize],
        expected_return: Option<BtfTypeId>,
    ) -> Self {
        let mut call_stack = parent_call_stack.to_vec();
        call_stack.push(target);
        Frame {
            registers,
            stack_objects: BTreeMap::new(),
            starting_pc: target,
            call_stack,
            expected_return,
        }
    }
}

/// The addressable stack, from the lowest byte to just past the top. Every
/// frame uses the whole `0..STACK_SIZE` range.
const STACK_RANGE: Range<u32> = 0..STACK_SIZE as u32;

/// How a walk came to exist.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub enum WalkOrigin {
    Branch {
        refined: Option<(u8, RegisterState)>,
        /// pc of the jump that spawned this arm.
        fork_pc: usize,
    },
    Fallthrough {
        refined: Option<(u8, RegisterState)>,
        /// pc of the jump that spawned this arm.
        fork_pc: usize,
    },
    Call,
}

/// The verifier owns the program and drives verification.
///
/// One per run. It tracks ids and records the snapshots that the [`Walk`]s
/// it spawns read and update through a shared borrow.
pub struct Verifier<'a> {
    vm: &'a Vm,
    prog: Arc<EbpfProgram>,
    config: &'a VerifierConfig,
    /// Walks get their own IDs are forks are created. Needed for reliably
    /// linkings events. Starts at 1, the root is 0.
    next_walk_id: Cell<usize>,
    /// Counter for distinct ids to each new packet-pointer register.
    next_pkt_id: Cell<u32>,
    /// Running maximum subprogram nesting depth over the whole verification.
    max_call_depth: Cell<usize>,
    /// States recorded per pc. A later, equal or narrower state reaching the
    /// same pc is pruned against them.
    snapshots: RefCell<BTreeMap<usize, Vec<StateSnapshot>>>,
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

        Ok(Verifier {
            vm,
            prog,
            config,
            next_walk_id: Cell::new(1),
            next_pkt_id: Cell::new(0),
            max_call_depth: Cell::new(0),
            snapshots: Default::default(),
        })
    }

    /// Run the verifier.
    ///
    /// On success, returns the max call depth and r0 register state.
    pub fn run(&self) -> Result<VerificationOutput, VerifierError> {
        let registers = registers_from_params(&self.prog.btf, &self.prog.func.params_types)?;
        Walk::root(self, registers).run()
    }

    /// Generates the next walk id.
    fn fresh_walk_id(&self) -> usize {
        let id = self.next_walk_id.get();
        self.next_walk_id.set(id + 1);
        id
    }

    /// Generates a new id for a packet-pointer register.
    fn fresh_pkt_id(&self) -> u32 {
        let id = self.next_pkt_id.get();
        self.next_pkt_id.set(id + 1);
        id
    }
}

/// Builds the entry-frame registers from the program's context parameters.
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
