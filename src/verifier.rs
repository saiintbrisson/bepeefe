use std::{collections::BTreeMap, ops::Range, sync::Arc};

use crate::{
    isa::{
        BPF_ALU32, BPF_ALU64, BPF_JMP, BPF_JMP32, BPF_LD, BPF_LDX, BPF_ST, BPF_STX, Insn,
        alu::{
            ALU_OP_MASK, BPF_ADD, BPF_ARSH, BPF_DIV, BPF_K, BPF_LSH, BPF_MOD, BPF_MOV, BPF_RSH,
            BPF_SUB, BPF_X,
        },
        jmp::{
            BPF_CALL, BPF_EXIT, BPF_HELPER_CALL, BPF_HELPER_TABLE, BPF_JA, BPF_JEQ, BPF_JNE,
            BPF_PSEUDO_CALL, JMP_OP_MASK,
        },
        load::{
            BPF_PSEUDO_MAP_FD, LOAD_MODE_MASK, LOAD_SIZE_MASK, MODE_ATOMIC, MODE_IMM, MODE_MEM,
            MODE_MEMSX, SIZE_B, SIZE_DW, SIZE_H, SIZE_W,
        },
    },
    object::EbpfProgram,
    vm::Vm,
};

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
    /// Pointer to a map value, returned from map_lookup_elem
    PtrToMapValue {
        map_fd: i32,
        offset: u32,
    },
    /// Null or pointer to map value
    PtrToMapValueOrNull {
        map_fd: i32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    U32(u32),
    U64(u64),
    Unknown,
}

impl Scalar {
    fn is_known(&self) -> bool {
        matches!(self, Self::U32(_) | Self::U64(_))
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

    stack_objects: BTreeMap<usize, usize>,
    stack_range: Range<usize>,
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

    stack_objects: BTreeMap<u32, u32>,
    stack_range: Range<u32>,
}

impl<'a> VerifierState<'a> {
    pub fn new(vm: &'a Vm, prog: Arc<EbpfProgram>) -> Self {
        assert!(prog.sig.params_types.len() <= 5);

        let mut registers = [RegisterState::Uninit; 11];

        for (idx, (_, ty)) in prog.sig.params_types.iter().enumerate() {
            let btf = prog.btf.as_ref().unwrap();
            let btf_type = btf.get_type(*ty).unwrap();
            let size = btf_type.kind.size(btf).unwrap();

            registers[idx + 1] = match btf_type.kind {
                crate::btf::BtfKind::Int(_) => RegisterState::Scalar(Scalar::Unknown),
                crate::btf::BtfKind::Ptr(_) => RegisterState::PtrToCtx { offset: 0, size },
                _ => todo!("not supported"),
            };
        }

        registers[10] = RegisterState::PtrToStack { pointer: 512 };

        Self {
            vm,
            prog,
            registers,
            starting_pc: 0,
            pc: 0,
            skip: 0,
            exit: false,
            stack_objects: Default::default(),
            stack_range: (0..512),
        }
    }

    pub fn run(&mut self) {
        let prog = &self.prog.clone();
        let mut iter = prog.insns.iter().enumerate().skip(self.pc as usize);

        while let Some((idx, insn)) = iter.by_ref().skip(self.skip).next() {
            self.skip = 0;
            self.pc = idx as isize + 1;

            eprintln!(
                "\n{idx}: {}: {}",
                crate::isa::INSTRUCTION_NAME_TABLE[insn.opcode() as usize],
                crate::vm::debugger::disasm(*insn, self.prog.insns.get(idx + 1).cloned())
            );

            self.check_insn(insn);

            if self.exit {
                break;
            }
        }
    }

    fn check_insn(&mut self, insn: &Insn) {
        if insn.class() != BPF_ST && insn.class() != BPF_STX && insn.dst_reg() == 10 {
            todo!("only ST, STX instructions can use SP register as dst")
        }

        if insn.dst_reg() > 10 {
            todo!("instruction contains invalid dst register")
        } else if insn.src_reg() > 10 {
            todo!("instruction contains invalid src register")
        }

        match insn.class() {
            BPF_ALU32 | BPF_ALU64 => self.check_alu(insn),
            BPF_LD => self.check_non_conventional_ld(insn),
            BPF_LDX => self.check_ldx(insn),
            BPF_ST | BPF_STX => self.check_st(insn),
            BPF_JMP32 | BPF_JMP => self.check_jmp(insn),
            _ => {}
        }

        let dump = self
            .registers
            .iter()
            .enumerate()
            .map(|(idx, state)| format!("r{idx}: {state:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!("{dump}");
    }

    fn mark_unknown(&mut self, reg: u8) {
        self.registers[reg as usize] = RegisterState::Scalar(Scalar::Unknown);
    }

    fn check_alu(&mut self, insn: &Insn) {
        let op = insn.opcode() & ALU_OP_MASK;

        let src = if insn.opcode() & BPF_X == BPF_X {
            assert_eq!(
                insn.imm(),
                0,
                "ALU uses reserved IMM field for register-sourced opcode"
            );

            let src_state = self.registers[insn.src_reg() as usize];
            assert_ne!(
                src_state,
                RegisterState::Uninit,
                "ALU instruction tried reading from unwritten register"
            );

            Some(src_state)
        } else {
            assert_eq!(
                insn.src_reg(),
                0,
                "ALU instruction uses reserved source register field"
            );

            None
        };

        let size = if insn.class() == BPF_ALU32 { 32 } else { 64 };
        let dst = insn.dst_reg();

        match (op, src) {
            (BPF_MOV, _) => return self.check_alu_mov(insn, src),

            (BPF_MOD | BPF_DIV, None) if insn.imm() == 0 => todo!("ALU division by IMM=0"),
            (BPF_LSH | BPF_RSH | BPF_ARSH, None) if insn.imm() < 0 || insn.imm() >= size => {
                todo!("ALU shift out of bounds {}", insn.imm())
            }

            (BPF_MOD | BPF_DIV, _) if insn.offset() != 0 || insn.offset() != 1 => {
                todo!("ALU instruction uses reserved offset field")
            }
            (_, _) if insn.offset() != 0 => todo!("ALU instruction uses reserved offset field"),

            _ => {}
        }

        // TODO: track scalar operations like add, sub, mul, etc
        // https://github.com/torvalds/linux/blob/ea1013c1539270e372fc99854bc6e4d94eaeff66/kernel/bpf/verifier.c#L15505

        if insn.class() != BPF_ALU64 {
            // TODO: track scalar operations like add, sub, mul, etc
            // 32bit ALU operations produce scalars
            self.mark_unknown(dst);
            return;
        }

        let alu_dst = self.registers[dst as usize];
        assert_ne!(
            alu_dst,
            RegisterState::Uninit,
            "ALU instruction using uninit dst register r{dst}"
        );

        if !alu_dst.is_pointer() {
            // TODO: track scalar operations like add, sub, mul, etc
            self.mark_unknown(dst);
            return;
        }

        // TODO: allow scalar += pointer operations
        let src_val = match src {
            Some(RegisterState::Scalar(Scalar::U32(val))) => val as i32,
            Some(RegisterState::Scalar(Scalar::U64(val))) => (val as i64)
                .try_into()
                .expect("ALU tried using way too large scalar for pointer arithmetic"),
            Some(RegisterState::Scalar(Scalar::Unknown)) => todo!(
                "ALU uses register with unknown scalar value r{}",
                insn.src_reg()
            ),
            None => insn.imm(),
            _ => todo!(
                "ALU instruction cannot operate with pointer src register r{}",
                insn.src_reg()
            ),
        };

        match op {
            BPF_ADD => {
                self.registers[dst as usize] = match alu_dst {
                    RegisterState::PtrToCtx { offset, size } => {
                        let offset = offset.checked_add_signed(src_val).unwrap();
                        assert!(size > offset, "ALU ADD overflowed the context");
                        RegisterState::PtrToCtx { offset, size }
                    }
                    RegisterState::PtrToStack { pointer } => {
                        let pointer = pointer.checked_add_signed(src_val).unwrap();
                        assert!(
                            pointer >= self.stack_range.start,
                            "ALU ADD overflowed the stack"
                        );
                        RegisterState::PtrToStack { pointer }
                    }
                    RegisterState::PtrToMapValue { map_fd, offset } => {
                        let offset = offset.checked_add_signed(src_val).unwrap();

                        let bpf_map = self.vm.map_by_fd(map_fd).unwrap();
                        let map_val = bpf_map.spec.value.unwrap();
                        assert!(
                            bpf_map.btf.is_offset_valid(map_val, offset, None).unwrap(),
                            "ALU ADD overflowed map value"
                        );

                        RegisterState::PtrToMapValue { map_fd, offset }
                    }
                    _ => todo!(),
                };
            }
            BPF_SUB => {
                self.registers[dst as usize] = match alu_dst {
                    RegisterState::PtrToCtx { offset, size } => {
                        todo!();
                    }
                    RegisterState::PtrToStack { pointer } => {
                        todo!("ALU SUB does not work on stack pointers")
                    }
                    RegisterState::PtrToMap { map_fd } => {
                        todo!();
                    }
                    _ => unreachable!(),
                };
            }

            _ => todo!("ALU64 pointer arithmetic only allowed with ADD and SUB operations"),
        }
    }

    /// Checks a ALU MOV instruction and updates registers.
    ///
    /// * Moving a pointer simply copies the pointer to DST,
    /// only ALU64 can perform pointer moves.
    /// * When moving known scalars, the value is trimmed
    /// according to the ALU class. If the insn is a MOVSX (sign-extension),
    /// the offset is checked and the known value is sign-extended
    /// accordingly.
    /// * Moving unknown scalars simply copy the unknown status.
    /// * Moving IMMs result in known scalars with size according to the class.
    fn check_alu_mov(&mut self, insn: &Insn, src: Option<RegisterState>) {
        self.registers[insn.dst_reg() as usize] = match src {
            Some(src) if src.is_pointer() => {
                assert_eq!(insn.class(), BPF_ALU64, "ALU32 MOV partial copy of pointer");
                assert_eq!(insn.offset(), 0, "ALU MOV with sign extension on pointer");

                src
            }
            Some(RegisterState::Scalar(scalar)) if scalar.is_known() => {
                let scalar = match (insn.class(), scalar) {
                    (BPF_ALU32, Scalar::U64(n)) => Scalar::U32(n as u32),
                    (BPF_ALU64, Scalar::U32(n)) => Scalar::U64(n as u64),
                    _ => scalar,
                };

                let scalar = match (insn.offset() as u32, scalar) {
                    (0, _) => scalar,
                    (offset @ (8 | 16), Scalar::U32(n)) => {
                        let shift = u32::BITS - offset;
                        Scalar::U32(((n as i32) << shift >> shift) as u32)
                    }
                    (offset @ (8 | 16 | 32), Scalar::U64(n)) => {
                        let shift = u64::BITS - offset;
                        Scalar::U64(((n as i64) << shift >> shift) as u64)
                    }
                    _ => todo!("ALU MOV uses invalid offset {}", insn.offset()),
                };

                RegisterState::Scalar(scalar)
            }
            Some(src @ RegisterState::Scalar(_)) => src,
            Some(_) => panic!("called with invalid src register"),
            None => {
                if insn.class() == BPF_ALU32 {
                    RegisterState::Scalar(Scalar::U32(insn.imm() as u32))
                } else {
                    RegisterState::Scalar(Scalar::U64(insn.imm() as u64))
                }
            }
        };
    }

    fn check_ldx(&mut self, insn: &Insn) {
        match insn.opcode() & LOAD_MODE_MASK {
            MODE_MEM => {
                let src = &self.registers[insn.src_reg() as usize];

                let load_size = match insn.opcode() & LOAD_SIZE_MASK {
                    SIZE_DW => 8,
                    SIZE_W => 4,
                    SIZE_H => 2,
                    SIZE_B => 1,
                    _ => unreachable!(),
                };

                match src {
                    &RegisterState::PtrToCtx { offset, size } => {
                        let read_offset = offset.checked_add_signed(insn.offset() as i32).unwrap();
                        if read_offset + load_size > size {
                            todo!("LD tried reading out of ctx bounds");
                        }
                    }
                    &RegisterState::PtrToStack { pointer } => {
                        let dst = pointer.checked_add_signed(insn.offset() as i32).unwrap();
                        assert_eq!(
                            *self.stack_objects.get(&dst).unwrap(),
                            load_size,
                            "LD tried reading outside of stack bounds"
                        );
                    }
                    RegisterState::PtrToMap { map_fd } => todo!(),
                    RegisterState::PtrToMapValue { map_fd, offset } => {
                        let bpf_map = self.vm.map_by_fd(*map_fd).unwrap();
                        let map_val = bpf_map.spec.value.unwrap();
                        let offset = offset.checked_add_signed(insn.offset() as i32).unwrap();
                        assert!(
                            bpf_map
                                .btf
                                .is_offset_valid(map_val, offset, Some(load_size))
                                .unwrap()
                        );
                    }
                    src => todo!("load source refers to invalid memory location: {src:?}"),
                }

                self.mark_unknown(insn.dst_reg());
            }
            MODE_MEMSX => todo!("sign-extension loads are not supported yet"),
            _ => todo!(),
        }
    }

    /// Checks for LD IMM64 instructions. For now,
    /// only IMM and MAP FD loads are supported. Signals
    /// for the verifier to skip next instruction.
    fn check_non_conventional_ld(&mut self, insn: &Insn) {
        assert_eq!(
            insn.opcode() & LOAD_MODE_MASK,
            MODE_IMM,
            "LD class is reserved for ld_imm64"
        );
        assert_eq!(
            insn.opcode() & LOAD_SIZE_MASK,
            SIZE_DW,
            "LD class is reserved for ld_imm64"
        );

        match insn.src_reg() {
            // TODO: it is a known value, just have to fetch it from next insn slot
            0 => self.mark_unknown(insn.dst_reg()),
            BPF_PSEUDO_MAP_FD => {
                let map_fd = insn.imm();
                assert!(
                    self.vm.map_by_fd_exists(map_fd),
                    "LD_IMM64 referenced non-existing FD"
                );
                self.registers[insn.dst_reg() as usize] = RegisterState::PtrToMap { map_fd }
            }
            v => todo!("LD_IMM64 pseudo function not supported: {v}"),
        }

        self.skip = 1;
    }

    fn check_st(&mut self, insn: &Insn) {
        let mode = insn.opcode() & LOAD_MODE_MASK;
        assert!(
            mode == MODE_MEM || mode == MODE_ATOMIC,
            "ST and STX only support MEM and ATOMIC mode"
        );
        let dst_reg = self.registers[insn.dst_reg() as usize];
        assert!(
            dst_reg.is_pointer(),
            "ST instruction tried storing to non-pointer register r{}",
            insn.src_reg()
        );

        let store_size = match insn.opcode() & LOAD_SIZE_MASK {
            SIZE_DW => 8,
            SIZE_W => 4,
            SIZE_H => 2,
            SIZE_B => 1,
            _ => unreachable!(),
        };

        match &self.registers[insn.dst_reg() as usize] {
            RegisterState::Uninit => todo!("ST writing to uninit register r{}", insn.dst_reg()),
            RegisterState::PtrToStack { pointer } => {
                let dst = pointer.checked_add_signed(insn.offset() as i32).unwrap();

                assert!(
                    dst.is_multiple_of(store_size),
                    "ST tried writing to unaligned address"
                );

                assert!(
                    self.stack_range.contains(&dst)
                        && self.stack_range.contains(&(dst + store_size - 1)),
                    "ST tried writing to outside the stack {}.. {}({store_size}) ..{}",
                    self.stack_range.start,
                    dst,
                    self.stack_range.end
                );

                let write_range = dst..dst + store_size;

                // TODO: do I allow overwrites and wipe existing stack in written range?

                for (addr, len) in self
                    .stack_objects
                    .range(dst.saturating_sub(4)..write_range.end)
                {
                    if *addr == dst && *len == store_size {
                        // allow overwrite with same addr and len
                        // we can break because we know previous writes ensured this was a safe operation
                        // and the entry is already written
                        return;
                    }

                    assert!(
                        !write_range.contains(addr) && !write_range.contains(&(*addr + *len)),
                        "ST tried writing within existing object range {addr}.. {dst}  ..{}",
                        addr + len
                    );
                }

                self.stack_objects.insert(dst, store_size);
            }
            RegisterState::PtrToMapValue { map_fd, offset } => {
                let bpf_map = self.vm.map_by_fd(*map_fd).unwrap();
                let map_val = bpf_map.spec.value.unwrap();
                let offset = offset.checked_add_signed(insn.offset() as i32).unwrap();
                assert!(
                    bpf_map
                        .btf
                        .is_offset_valid(map_val, offset, Some(store_size))
                        .unwrap()
                );
            }
            _ => todo!(),
        }
    }

    fn check_jmp(&mut self, insn: &Insn) {
        let jmp_op = insn.opcode() & JMP_OP_MASK;

        if jmp_op == BPF_CALL {
            self.check_jmp_call(insn);
            return;
        }

        if jmp_op == BPF_EXIT {
            assert_eq!(insn.offset(), 0, "JMP EXIT uses reserved offset field");
            assert_eq!(insn.src_reg(), 0, "JMP EXIT uses reserved offset field");
            assert_eq!(
                insn.opcode() & 0b1111,
                BPF_JMP | BPF_K,
                "JMP EXIT must be BPF_JMP | BPF_K"
            );
            self.exit = true;
            return;
        }

        let offset = if insn.opcode() == BPF_JMP32 | BPF_K | BPF_JA {
            insn.imm()
        } else {
            insn.offset() as i32
        };
        let target_pc = self.pc + offset as isize;

        if offset == -1 {
            todo!("JMP causes infinite halt");
        } else if target_pc < self.starting_pc || target_pc >= self.prog.insns.len() as isize {
            todo!("JMP invalid offset");
        }

        if jmp_op == BPF_JA {
            let mut new = VerifierState {
                starting_pc: target_pc,
                pc: target_pc,
                ..self.clone()
            };

            new.run();

            // TODO: this is an unconditional jump
            // we shouldnt run it in a separate state
            // just override the current PC

            self.exit = true;

            return;
        }

        if self.registers[insn.dst_reg() as usize].is_uninint() {
            todo!("JMP comparing uninit dst register r{}", insn.dst_reg());
        } else if insn.opcode() & 0b1000 == BPF_X
            && self.registers[insn.src_reg() as usize].is_uninint()
        {
            todo!("JMP comparing uninit src register r{}", insn.src_reg());
        }

        let mut branch_vm = VerifierState {
            starting_pc: target_pc,
            pc: target_pc,
            ..self.clone()
        };

        let rhs_val = if insn.opcode() & BPF_X == BPF_X {
            match self.registers[insn.src_reg() as usize] {
                RegisterState::Uninit => todo!("JMP using uninit register r{}", insn.src_reg()),
                RegisterState::Scalar(Scalar::U32(val)) => val as u64,
                RegisterState::Scalar(Scalar::U64(val)) => val,
                _ => return branch_vm.run(),
            }
        } else {
            insn.imm() as u64
        };

        let RegisterState::PtrToMapValueOrNull { map_fd } =
            branch_vm.registers[insn.dst_reg() as usize]
        else {
            return branch_vm.run();
        };

        match jmp_op {
            BPF_JNE if rhs_val == 0 => {
                branch_vm.registers[insn.dst_reg() as usize] =
                    RegisterState::PtrToMapValue { map_fd, offset: 0 };
            }
            BPF_JEQ if rhs_val == 0 => {
                self.registers[insn.dst_reg() as usize] =
                    RegisterState::PtrToMapValue { map_fd, offset: 0 };
            }
            _ => {}
        }

        branch_vm.run();
    }

    fn check_jmp_call(&mut self, insn: &Insn) {
        assert_eq!(
            insn.opcode() & 0b1111,
            BPF_JMP | BPF_K,
            "JMP CALL must be BPF_JMP | BPF_K"
        );

        match insn.src_reg() {
            BPF_PSEUDO_CALL => todo!("sub-program calls are not supported  yet"),
            BPF_HELPER_CALL => {
                let helper_id = insn.imm() as usize;
                (BPF_HELPER_TABLE[helper_id].params)(&self.registers, *insn).unwrap();

                self.registers[0] = (BPF_HELPER_TABLE[helper_id].retval)(&self.registers, *insn);
            }
            _ => {}
        }
    }
}
