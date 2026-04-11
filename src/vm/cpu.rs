use std::{borrow::Cow, sync::Arc};

use super::{PreparedProgram, STACK_SIZE, env::HostEnv, ptr::TaggedPtr};
use crate::{capture::Capture, isa::Insn, maps::BpfMap};

/// Initial entry-point state laid out by `PreparedProgram::build_image`.
///
/// The image is bound to the `PreparedProgram` it was built against; a
/// `Cpu` can only be constructed from an image that matches its
/// program.
pub struct CtxImage {
    pub(super) prog: Arc<PreparedProgram>,
    pub(super) ctx_buf: Vec<u8>,
    pub(super) arg_regs: Vec<(u8, u64)>,
}

pub(crate) struct StackFrame {
    ret_addr: usize,
    registers: [u64; 4],
}

pub struct Cpu {
    prog: Arc<PreparedProgram>,
    buf: Vec<u8>,
    pc: usize,
    registers: [u64; 11],
    exit: bool,
    call_stack: Vec<StackFrame>,
    env: HostEnv,
    capture: Option<Arc<dyn Capture>>,
}

impl Cpu {
    pub(super) fn new(env: HostEnv, capture: Option<Arc<dyn Capture>>, image: CtxImage) -> Self {
        let prog = image.prog;
        let call_frames = (1 + prog.max_call_depth).max(1);
        let buf_len = image.ctx_buf.len() + STACK_SIZE * call_frames;

        let mut buf = image.ctx_buf;
        buf.resize(buf_len, 0);

        let mut state = Self {
            prog,
            buf,
            pc: 0,
            registers: [0; 11],
            exit: false,
            call_stack: Vec::with_capacity(call_frames.saturating_sub(1)),
            env,
            capture,
        };
        state.set_reg(10, TaggedPtr::local(buf_len as u32 - 1));
        for (idx, val) in image.arg_regs {
            state.set_reg(idx, val);
        }
        state
    }

    /// Fetches and dispatches one instruction. Returns `true` once the
    /// program has finished (either via exit or by running off the end).
    pub fn step(&mut self) -> bool {
        if self.exit {
            return true;
        }
        let Some(insn) = self.prog.prog.insns.get(self.pc).copied() else {
            self.exit = true;
            return true;
        };
        self.pc += 1;
        crate::isa::insn_handler(insn)(self, insn);
        self.exit
    }

    pub fn pc(&self) -> usize {
        self.pc
    }

    pub fn advance_pc(&mut self) {
        self.pc += 1;
    }

    pub fn advance_pc_by(&mut self, offset: isize) {
        self.pc = (self.pc as isize + offset) as usize;
    }

    pub fn insn_at(&self, pc: usize) -> Option<Insn> {
        self.prog.prog.insns.get(pc).copied()
    }

    pub fn done(&self) -> bool {
        self.exit
    }

    pub fn exit(&mut self) {
        self.exit = true;
    }

    pub fn env(&self) -> &HostEnv {
        &self.env
    }

    pub fn capture(&self) -> Option<&Arc<dyn Capture>> {
        self.capture.as_ref()
    }

    /// # Panics
    ///
    /// Panics if `fd` is not a known map FD. All callers reach this
    /// through verifier-validated register states.
    pub(crate) fn get_map(&self, fd: u16) -> Arc<BpfMap> {
        self.prog.vm.get_map(fd)
    }

    pub fn prandom_u32(&self) -> u32 {
        self.prog.vm.prandom_u32()
    }

    /// # Panics
    ///
    /// Panics if `idx` is out of bounds (>= 11). Callers are expected to
    /// have checked before calling, for example by passing a program
    /// through the verifier.
    #[inline(always)]
    #[expect(
        clippy::indexing_slicing,
        reason = "register index is caller-validated to be < 11"
    )]
    pub fn reg(&self, idx: u8) -> u64 {
        self.registers[idx as usize]
    }

    /// # Panics
    ///
    /// Panics if `idx` is out of bounds (>= 11). Callers are expected to
    /// have checked before calling, for example by passing a program
    /// through the verifier.
    #[inline(always)]
    #[expect(
        clippy::indexing_slicing,
        reason = "register index is caller-validated to be < 11"
    )]
    pub fn set_reg(&mut self, idx: u8, val: u64) {
        self.registers[idx as usize] = val;
    }

    pub fn regs(&self) -> [u64; 11] {
        self.registers
    }

    /// Convenience for `reg(0)`, the BPF return value register.
    pub fn return_val(&self) -> u64 {
        self.reg(0)
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf
    }

    /// # Panics
    ///
    /// Panics if `offset..offset + len` is out of bounds. Callers are
    /// expected to have checked before calling, for example by passing
    /// a program through the verifier.
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "caller is expected to run verifier"
    )]
    fn buf_slice(&self, offset: usize, len: usize) -> &[u8] {
        &self.buf[offset..offset + len]
    }

    /// # Panics
    ///
    /// Panics if `offset..offset + len` is out of bounds. Callers are
    /// expected to have checked before calling, for example by passing
    /// a program through the verifier.
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "caller is expected to run verifier"
    )]
    fn buf_slice_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        &mut self.buf[offset..offset + len]
    }

    #[inline]
    #[expect(clippy::unwrap_used, reason = "buf_slice returns exactly N bytes")]
    fn local_read<const N: usize>(&self, offset: usize) -> [u8; N] {
        self.buf_slice(offset, N).try_into().unwrap()
    }

    #[expect(clippy::unwrap_used, reason = "caller is expected to run verifier")]
    pub fn read<const SIZE: usize>(&self, ptr: u64) -> [u8; SIZE] {
        match TaggedPtr::decode(ptr) {
            TaggedPtr::Map { fd, offset } => {
                let map = self.get_map(fd);
                map.repr.read(offset as usize).unwrap()
            }
            TaggedPtr::Local { offset } => self.local_read(offset as usize),
            _ => [0; SIZE],
        }
    }

    #[expect(clippy::unwrap_used, reason = "caller is expected to run verifier")]
    pub fn write(&mut self, ptr: u64, src: &[u8]) {
        match TaggedPtr::decode(ptr) {
            TaggedPtr::Map { fd, offset } => {
                let map = self.get_map(fd);
                map.repr.write(offset as usize, src).unwrap();
            }
            TaggedPtr::Local { offset } => {
                self.buf_slice_mut(offset as usize, src.len())
                    .copy_from_slice(src);
            }
            _ => {}
        }
    }

    #[expect(clippy::unwrap_used, reason = "caller is expected to run verifier")]
    pub fn read_bytes(&self, ptr: u64, len: usize) -> Cow<'_, [u8]> {
        match TaggedPtr::decode(ptr) {
            TaggedPtr::Map { fd, offset } => {
                let map = self.get_map(fd);
                map.repr.read_bytes(offset as usize, len).unwrap().into()
            }
            TaggedPtr::Local { offset } => self.buf_slice(offset as usize, len).into(),
            _ => vec![].into(),
        }
    }

    pub fn try_buf(&self, ptr: u64) -> Option<&[u8]> {
        match TaggedPtr::try_decode(ptr)? {
            TaggedPtr::Local { offset } => self.buf.get(offset as usize..),
            _ => None,
        }
    }

    pub fn call(&mut self, offset: i32) {
        self.call_stack.push(StackFrame {
            ret_addr: self.pc,
            registers: [self.reg(6), self.reg(7), self.reg(8), self.reg(9)],
        });

        self.set_reg(10, self.reg(10) - STACK_SIZE as u64);
        self.advance_pc_by(offset as isize);
    }

    pub fn call_exit(&mut self) {
        let Some(frame) = self.call_stack.pop() else {
            self.exit = true;
            return;
        };

        self.pc = frame.ret_addr;
        self.set_reg(10, self.reg(10) + STACK_SIZE as u64);
        // R6-R9 are callee-saved while R1-R5 are caller-saved (reset to
        // unreadable on return).
        // https://github.com/torvalds/linux/blob/master/Documentation/bpf/classic_vs_extended.rst
        for i in 1..=5 {
            self.set_reg(i, 0);
        }
        for (offset, val) in frame.registers.iter().enumerate() {
            self.set_reg(6 + offset as u8, *val);
        }
    }
}
