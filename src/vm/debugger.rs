use crate::isa::Insn;

#[derive(Clone, Copy)]
pub enum InsnKind {
    AluSrc(&'static str),
    AluImm(&'static str),
    AluImmSigned,
    Neg,
    MovSrc,
    MovImm,
    Bswap,
    Load(&'static str),
    Store(&'static str),
    LdImm64,
    Atomic,
    JmpSrc(&'static str),
    JmpImm(&'static str),
    Ja32,
    Ja64,
    Call,
    Exit,
    Unknown,
}

pub fn describe(opcode: u8) -> InsnKind {
    match crate::isa::INSTRUCTION_NAME_TABLE[opcode as usize] {
        "add_src_32" | "add_src_64" => InsnKind::AluSrc("+"),
        "sub_src_32" | "sub_src_64" => InsnKind::AluSrc("-"),
        "mul_src_32" | "mul_src_64" => InsnKind::AluSrc("*"),
        "div_src_32" | "div_src_64" => InsnKind::AluSrc("/"),
        "mod_src_32" | "mod_src_64" => InsnKind::AluSrc("%"),
        "or_src_32" | "or_src_64" => InsnKind::AluSrc("|"),
        "and_src_32" | "and_src_64" => InsnKind::AluSrc("&"),
        "xor_src_32" | "xor_src_64" => InsnKind::AluSrc("^"),
        "lsh_src_32" | "lsh_src_64" => InsnKind::AluSrc("<<"),
        "rsh_src_32" | "rsh_src_64" => InsnKind::AluSrc(">>"),
        "arsh_src_32" | "arsh_src_64" => InsnKind::AluSrc("s>>"),

        "add_imm_32" | "add_imm_64" => InsnKind::AluImmSigned,
        "sub_imm_32" | "sub_imm_64" => InsnKind::AluImm("-"),
        "mul_imm_32" | "mul_imm_64" => InsnKind::AluImm("*"),
        "div_imm_32" | "div_imm_64" => InsnKind::AluImm("/"),
        "mod_imm_32" | "mod_imm_64" => InsnKind::AluImm("%"),
        "or_imm_32" | "or_imm_64" => InsnKind::AluImm("|"),
        "and_imm_32" | "and_imm_64" => InsnKind::AluImm("&"),
        "xor_imm_32" | "xor_imm_64" => InsnKind::AluImm("^"),
        "lsh_imm_32" | "lsh_imm_64" => InsnKind::AluImm("<<"),
        "rsh_imm_32" | "rsh_imm_64" => InsnKind::AluImm(">>"),
        "arsh_imm_32" | "arsh_imm_64" => InsnKind::AluImm("s>>"),

        "neg_imm_32" | "neg_imm_64" => InsnKind::Neg,
        "mov_src_32" | "mov_src_64" => InsnKind::MovSrc,
        "mov_imm_32" | "mov_imm_64" => InsnKind::MovImm,
        "le" | "be" | "swap" => InsnKind::Bswap,

        "ldx_mem_b" => InsnKind::Load("*(u8 *)"),
        "ldx_mem_h" => InsnKind::Load("*(u16 *)"),
        "ldx_mem_w" => InsnKind::Load("*(u32 *)"),
        "ldx_mem_dw" => InsnKind::Load("*(u64 *)"),

        "stx_mem_b" => InsnKind::Store("*(u8 *)"),
        "stx_mem_h" => InsnKind::Store("*(u16 *)"),
        "stx_mem_w" => InsnKind::Store("*(u32 *)"),
        "stx_mem_dw" => InsnKind::Store("*(u64 *)"),

        "ld_imm64" => InsnKind::LdImm64,
        "stx_atomic_dw" => InsnKind::Atomic,

        "jeq_src_32" | "jeq_src_64" => InsnKind::JmpSrc("=="),
        "jgt_src_32" | "jgt_src_64" => InsnKind::JmpSrc(">"),
        "jge_src_32" | "jge_src_64" => InsnKind::JmpSrc(">="),
        "jlt_src_32" | "jlt_src_64" => InsnKind::JmpSrc("<"),
        "jle_src_32" | "jle_src_64" => InsnKind::JmpSrc("<="),
        "jset_src_32" | "jset_src_64" => InsnKind::JmpSrc("&"),
        "jne_src_32" | "jne_src_64" => InsnKind::JmpSrc("!="),
        "jsgt_src_32" | "jsgt_src_64" => InsnKind::JmpSrc("s>"),
        "jsge_src_32" | "jsge_src_64" => InsnKind::JmpSrc("s>="),
        "jslt_src_32" | "jslt_src_64" => InsnKind::JmpSrc("s<"),
        "jsle_src_32" | "jsle_src_64" => InsnKind::JmpSrc("s<="),

        "jeq_imm_32" | "jeq_imm_64" => InsnKind::JmpImm("=="),
        "jgt_imm_32" | "jgt_imm_64" => InsnKind::JmpImm(">"),
        "jge_imm_32" | "jge_imm_64" => InsnKind::JmpImm(">="),
        "jlt_imm_32" | "jlt_imm_64" => InsnKind::JmpImm("<"),
        "jle_imm_32" | "jle_imm_64" => InsnKind::JmpImm("<="),
        "jset_imm_32" | "jset_imm_64" => InsnKind::JmpImm("&"),
        "jne_imm_32" | "jne_imm_64" => InsnKind::JmpImm("!="),
        "jsgt_imm_32" | "jsgt_imm_64" => InsnKind::JmpImm("s>"),
        "jsge_imm_32" | "jsge_imm_64" => InsnKind::JmpImm("s>="),
        "jslt_imm_32" | "jslt_imm_64" => InsnKind::JmpImm("s<"),
        "jsle_imm_32" | "jsle_imm_64" => InsnKind::JmpImm("s<="),

        "ja_32" => InsnKind::Ja32,
        "ja_64" => InsnKind::Ja64,
        "jmp_call" => InsnKind::Call,
        "exit" => InsnKind::Exit,

        _ => InsnKind::Unknown,
    }
}

fn fmt_offset(off: i16) -> String {
    if off >= 0 {
        format!("+ 0x{:X}", off)
    } else {
        format!("- 0x{:X}", off.abs())
    }
}

fn fmt_imm_signed(imm: i32) -> String {
    if imm >= 0 {
        format!("+ 0x{:X}", imm)
    } else {
        format!("- 0x{:X}", imm.abs())
    }
}

fn fmt_goto(off: i16) -> String {
    if off >= 0 {
        format!("goto +{}", off)
    } else {
        format!("goto {}", off)
    }
}

fn fmt_goto_imm(imm: i32) -> String {
    if imm >= 0 {
        format!("goto +{}", imm)
    } else {
        format!("goto {}", imm)
    }
}

pub fn disasm(insn: Insn, next: Option<Insn>) -> String {
    let dst = insn.dst_reg();
    let src = insn.src_reg();
    let imm = insn.imm();
    let off = insn.offset();

    match describe(insn.opcode()) {
        InsnKind::AluSrc(op) => format!("r{} = r{} {} r{}", dst, dst, op, src),
        InsnKind::AluImm(op) => format!("r{} = r{} {} 0x{:X}", dst, dst, op, imm as u32),
        InsnKind::AluImmSigned => format!("r{} = r{} {}", dst, dst, fmt_imm_signed(imm)),
        InsnKind::Neg => format!("r{} = ~r{}", dst, dst),
        InsnKind::MovSrc => format!("r{} = r{}", dst, src),
        InsnKind::MovImm => format!("r{} = 0x{:X}", dst, imm as u32),
        InsnKind::Bswap => format!("r{} = bswap r{}", dst, dst),
        InsnKind::Load(size) => format!("r{} = {}(r{} {})", dst, size, src, fmt_offset(off)),
        InsnKind::Store(size) => format!("{}(r{} {}) = r{}", size, dst, fmt_offset(off), src),
        InsnKind::LdImm64 => {
            let imm_u = imm as u32 as u64;
            let next_imm = next.map(|i| i.imm() as u32 as u64).unwrap_or(0);
            match src {
                0 => format!("r{} = 0x{:X}", dst, imm_u | (next_imm << 32)),
                1 => format!("r{} = map_by_fd({})", dst, imm_u),
                2 => format!("r{} = map_val({}) + 0x{:X}", dst, imm_u, next_imm),
                3 => format!("r{} = var({})", dst, imm_u),
                4 => format!("r{} = code({})", dst, imm_u),
                5 => format!("r{} = map_by_idx({})", dst, imm_u),
                6 => format!("r{} = map_val_idx({}) + 0x{:X}", dst, imm_u, next_imm),
                _ => format!("r{} = imm64(?)", dst),
            }
        }
        InsnKind::Atomic => format!("lock *(u64 *)(r{} {}) += r{}", dst, fmt_offset(off), src),
        InsnKind::JmpSrc(cmp) => format!("if r{} {} r{} {}", dst, cmp, src, fmt_goto(off)),
        InsnKind::JmpImm(cmp) => {
            format!("if r{} {} 0x{:X} {}", dst, cmp, imm as u32, fmt_goto(off))
        }
        InsnKind::Ja32 => fmt_goto_imm(imm),
        InsnKind::Ja64 => fmt_goto(off),
        InsnKind::Call => match src {
            0 => format!("call {}", imm),
            1 if imm >= 0 => format!("call +{}", imm),
            1 => format!("call {}", imm),
            _ => format!("call ?{}", imm),
        },
        InsnKind::Exit => "exit".into(),
        InsnKind::Unknown => String::new(),
    }
}

pub fn disasm_brief(insn: Insn, next: Option<Insn>) -> String {
    let dst = insn.dst_reg();
    let src = insn.src_reg();
    let imm = insn.imm();
    let off = insn.offset();

    match describe(insn.opcode()) {
        InsnKind::AluSrc(op) => format!("r{} {} r{}", dst, op, src),
        InsnKind::AluImm(op) => format!("r{} {} 0x{:X}", dst, op, imm as u32),
        InsnKind::AluImmSigned => format!("r{} {}", dst, fmt_imm_signed(imm)),
        InsnKind::Neg => format!("~r{}", dst),
        InsnKind::MovSrc => format!("r{}", src),
        InsnKind::MovImm => format!("0x{:X}", imm as u32),
        InsnKind::Bswap => format!("bswap r{}", dst),
        InsnKind::Load(_) => format!("r{} {}", src, fmt_offset(off)),
        InsnKind::Store(_) => format!("r{} {} = r{}", dst, fmt_offset(off), src),
        InsnKind::LdImm64 => {
            let imm_u = imm as u32 as u64;
            let next_imm = next.map(|i| i.imm() as u32 as u64).unwrap_or(0);
            match src {
                0 => format!("0x{:X}", imm_u | (next_imm << 32)),
                1 => format!("map_by_fd({})", imm_u),
                2 => format!("map_val({}) + 0x{:X}", imm_u, next_imm),
                3 => format!("var({})", imm_u),
                4 => format!("code({})", imm_u),
                5 => format!("map_by_idx({})", imm_u),
                6 => format!("map_val_idx({}) + 0x{:X}", imm_u, next_imm),
                _ => "imm64(?)".into(),
            }
        }
        InsnKind::Atomic => format!("r{} {} += r{}", dst, fmt_offset(off), src),
        InsnKind::JmpSrc(cmp) => format!("r{} {} r{}", dst, cmp, src),
        InsnKind::JmpImm(cmp) => format!("r{} {} 0x{:X}", dst, cmp, imm as u32),
        InsnKind::Ja32 | InsnKind::Ja64 | InsnKind::Call | InsnKind::Exit => String::new(),
        InsnKind::Unknown => String::new(),
    }
}

pub fn debugger(vm: &super::Vm, insn: Insn) -> String {
    let dst = insn.dst_reg();
    let src = insn.src_reg();
    let imm = insn.imm();
    let off = insn.offset();
    let dst_val = vm.registers[dst as usize];
    let src_val = vm.registers[src as usize];
    let next = vm.code.peek();

    let brief = disasm_brief(insn, next);
    let ann = if brief.is_empty() {
        String::new()
    } else {
        format!(" [{}]", brief)
    };

    match describe(insn.opcode()) {
        InsnKind::AluSrc(op) => format!("r{} = 0x{:X} {} 0x{:X}{}", dst, dst_val, op, src_val, ann),
        InsnKind::AluImm(op) => format!(
            "r{} = 0x{:X} {} 0x{:X}{}",
            dst, dst_val, op, imm as u32, ann
        ),
        InsnKind::AluImmSigned => {
            format!("r{} = 0x{:X} {}{}", dst, dst_val, fmt_imm_signed(imm), ann)
        }
        InsnKind::Neg => format!("r{} = ~0x{:X}{}", dst, dst_val, ann),
        InsnKind::MovSrc => format!("r{} = 0x{:X}{}", dst, src_val, ann),
        InsnKind::MovImm => format!("r{} = 0x{:X}{}", dst, imm as u32, ann),
        InsnKind::Bswap => format!("r{} = bswap 0x{:X}{}", dst, dst_val, ann),
        InsnKind::Load(size) => {
            let addr = src_val.wrapping_add(off as i64 as u64);
            format!("r{} = {}0x{:X}{}", dst, size, addr, ann)
        }
        InsnKind::Store(size) => {
            let addr = dst_val.wrapping_add(off as i64 as u64);
            format!("{}0x{:X} = 0x{:X}{}", size, addr, src_val, ann)
        }
        InsnKind::LdImm64 => disasm(insn, next),
        InsnKind::Atomic => {
            let addr = dst_val.wrapping_add(off as i64 as u64);
            format!("lock *(u64 *)0x{:X} += 0x{:X}{}", addr, src_val, ann)
        }
        InsnKind::JmpSrc(cmp) => {
            format!(
                "if 0x{:X} {} 0x{:X} {}{}",
                dst_val,
                cmp,
                src_val,
                fmt_goto(off),
                ann
            )
        }
        InsnKind::JmpImm(cmp) => {
            format!(
                "if 0x{:X} {} 0x{:X} {}{}",
                dst_val,
                cmp,
                imm as u32,
                fmt_goto(off),
                ann
            )
        }
        InsnKind::Ja32 => fmt_goto_imm(imm),
        InsnKind::Ja64 => fmt_goto(off),
        InsnKind::Call => disasm(insn, next),
        InsnKind::Exit => "exit".into(),
        InsnKind::Unknown => String::new(),
    }
}
