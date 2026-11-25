use std::ops::DerefMut;
use std::sync::Arc;

use crate::capture::Capture;
use crate::maps::BpfMap;
use crate::vm::{Cpu, Task, World};

/// What a helper can reach of the running program besides its arguments.
pub struct Call<'c> {
    cpu: &'c mut Cpu,
}

impl<'c> Call<'c> {
    pub(super) fn new(cpu: &'c mut Cpu) -> Self {
        Self { cpu }
    }

    /// Writes the head of `bytes` that fits in `dst`.
    pub fn write(&mut self, dst: &Out, bytes: &[u8]) {
        let n = bytes.len().min(dst.len);
        self.cpu.write(dst.ptr, bytes.get(..n).unwrap_or_default());
    }

    /// Local memory from `ptr` to the end of its region, for the NUL
    /// terminated strings `trace_printk` takes as untyped arguments.
    pub fn local_tail(&self, ptr: u64) -> Option<&[u8]> {
        self.cpu.try_buf(ptr)
    }

    pub fn task(&self) -> &Task {
        self.cpu.task()
    }

    pub fn world(&self) -> impl DerefMut<Target = World> + '_ {
        self.cpu.world()
    }

    pub fn ktime_ns(&self) -> u64 {
        self.cpu.ktime_ns()
    }

    pub fn cpu(&self) -> u32 {
        self.cpu.cpu()
    }

    pub fn prandom_u32(&self) -> u32 {
        self.cpu.prandom_u32()
    }

    pub fn capture(&self) -> Option<&Arc<dyn Capture>> {
        self.cpu.capture()
    }

    pub fn pc(&self) -> usize {
        self.cpu.pc()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgSpec {
    /// Any initialized register. Linux's `ARG_ANYTHING`.
    Anything,
    Scalar,
    Ctx,
    Map,
    /// Reads `key_size` bytes of the closest preceding [`ArgSpec::Map`].
    MapKey,
    /// Reads `value_size` bytes of the closest preceding [`ArgSpec::Map`].
    MapValue,
    /// Writes `value_size` bytes of the closest preceding [`ArgSpec::Map`].
    UninitMapValue,
    /// A pointer in one register and its length in the next.
    Mem(Access),
    /// Like [`ArgSpec::Mem`], but NULL is accepted along with a zero length.
    #[expect(dead_code)]
    MemOrNull(Access),
    /// Neither checked nor marked as read. Linux's `ARG_DONTCARE`, used by
    /// variadic helpers like `trace_printk`.
    DontCare,
}

impl ArgSpec {
    pub const fn regs(self) -> u8 {
        match self {
            Self::Mem(_) | Self::MemOrNull(_) => 2,
            _ => 1,
        }
    }
}

pub struct Cursor<'c> {
    cpu: &'c Cpu,
    reg: u8,
    map: Option<Arc<BpfMap>>,
}

impl Cursor<'_> {
    fn next(&mut self, spec: ArgSpec) -> u64 {
        let val = self.cpu.reg(self.reg);
        self.reg += spec.regs();
        val
    }

    fn len_after(&self, reg: u8) -> usize {
        self.cpu.reg(reg) as usize
    }

    fn map_sizes(&self) -> (usize, usize) {
        self.map
            .as_ref()
            .and_then(|map| map.repr.sizes())
            .unwrap_or_default()
    }
}

pub trait Arg: Sized {
    const SPEC: ArgSpec;
    fn decode(cur: &mut Cursor<'_>) -> Self;
}

pub trait ArgList: Sized {
    const SIG: &'static [ArgSpec];
    fn decode(cpu: &Cpu) -> Self;
}

macro_rules! arg_list {
    ($($t:ident),*) => {
        impl<$($t: Arg),*> ArgList for ($($t,)*) {
            const SIG: &'static [ArgSpec] = &[$($t::SPEC),*];

            #[allow(unused_variables, unused_mut, clippy::unused_unit)]
            fn decode(cpu: &Cpu) -> Self {
                let mut cur = Cursor { cpu, reg: 1, map: None };
                ($($t::decode(&mut cur),)*)
            }
        }
    };
}

arg_list!();
arg_list!(A);
arg_list!(A, B);
arg_list!(A, B, C);
arg_list!(A, B, C, D);
arg_list!(A, B, C, D, E);

pub struct Any(pub u64);

impl Arg for Any {
    const SPEC: ArgSpec = ArgSpec::Anything;
    fn decode(cur: &mut Cursor<'_>) -> Self {
        Self(cur.next(Self::SPEC))
    }
}

pub struct Num(pub u64);

impl Arg for Num {
    const SPEC: ArgSpec = ArgSpec::Scalar;
    fn decode(cur: &mut Cursor<'_>) -> Self {
        Self(cur.next(Self::SPEC))
    }
}

pub struct Raw(pub u64);

impl Arg for Raw {
    const SPEC: ArgSpec = ArgSpec::DontCare;
    fn decode(cur: &mut Cursor<'_>) -> Self {
        Self(cur.next(Self::SPEC))
    }
}

pub struct Ctx;

impl Arg for Ctx {
    const SPEC: ArgSpec = ArgSpec::Ctx;
    fn decode(cur: &mut Cursor<'_>) -> Self {
        cur.next(Self::SPEC);
        Self
    }
}

pub struct Map {
    /// The program's slot for this map, what map pointers carry.
    pub idx: u16,
    pub map: Arc<BpfMap>,
}

impl Arg for Map {
    const SPEC: ArgSpec = ArgSpec::Map;
    fn decode(cur: &mut Cursor<'_>) -> Self {
        let idx = cur.next(Self::SPEC) as u16;
        let map = cur.cpu.get_map(idx);
        cur.map = Some(map.clone());
        Self { idx, map }
    }
}

pub struct Key(pub Vec<u8>);

impl Arg for Key {
    const SPEC: ArgSpec = ArgSpec::MapKey;
    fn decode(cur: &mut Cursor<'_>) -> Self {
        let (key_size, _) = cur.map_sizes();
        let ptr = cur.next(Self::SPEC);
        Self(cur.cpu.read_bytes(ptr, key_size).into_owned())
    }
}

pub struct Value(pub Vec<u8>);

impl Arg for Value {
    const SPEC: ArgSpec = ArgSpec::MapValue;
    fn decode(cur: &mut Cursor<'_>) -> Self {
        let (_, value_size) = cur.map_sizes();
        let ptr = cur.next(Self::SPEC);
        Self(cur.cpu.read_bytes(ptr, value_size).into_owned())
    }
}

pub struct ValueOut(pub Out);

impl Arg for ValueOut {
    const SPEC: ArgSpec = ArgSpec::UninitMapValue;
    fn decode(cur: &mut Cursor<'_>) -> Self {
        let (_, len) = cur.map_sizes();
        let ptr = cur.next(Self::SPEC);
        Self(Out { ptr, len })
    }
}

pub struct In(pub Vec<u8>);

impl Arg for In {
    const SPEC: ArgSpec = ArgSpec::Mem(Access::Read);
    fn decode(cur: &mut Cursor<'_>) -> Self {
        let len = cur.len_after(cur.reg + 1);
        let ptr = cur.next(Self::SPEC);
        Self(cur.cpu.read_bytes(ptr, len).into_owned())
    }
}

#[expect(dead_code)]
pub struct InOrNull(pub Option<Vec<u8>>);

impl Arg for InOrNull {
    const SPEC: ArgSpec = ArgSpec::MemOrNull(Access::Read);
    fn decode(cur: &mut Cursor<'_>) -> Self {
        let len = cur.len_after(cur.reg + 1);
        let ptr = cur.next(Self::SPEC);
        Self((ptr != 0).then(|| cur.cpu.read_bytes(ptr, len).into_owned()))
    }
}

/// Program memory a helper may write to, at most [`Out::size`] bytes.
pub struct Out {
    ptr: u64,
    len: usize,
}

impl Out {
    pub fn size(&self) -> usize {
        self.len
    }
}

impl Arg for Out {
    const SPEC: ArgSpec = ArgSpec::Mem(Access::Write);
    fn decode(cur: &mut Cursor<'_>) -> Self {
        let len = cur.len_after(cur.reg + 1);
        let ptr = cur.next(Self::SPEC);
        Self { ptr, len }
    }
}
