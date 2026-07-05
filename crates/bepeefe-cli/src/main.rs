//! BPF/BTF inspector.

mod btf;
mod core;
mod maps;
mod programs;
mod render;

use std::{path::PathBuf, process::ExitCode};

use bepeefe::EbpfObject;
use clap::{Parser, Subcommand};
use tabled::{Table, Tabled, settings::Style};

/// Builds a borderless table. The plain style keeps rows easy to copy and
/// paste.
fn table<T: Tabled>(rows: impl IntoIterator<Item = T>) -> Table {
    let mut table = Table::new(rows);
    table.with(Style::empty());
    table
}

/// Prints a navigation hint to stderr so it never mixes into piped output.
fn hint(body: &str) {
    eprintln!("\n{body}");
}

const EXAMPLES: &str = "\
Examples:
  bepeefe-cli obj.o                     overview
  bepeefe-cli obj.o programs            list programs
  bepeefe-cli obj.o programs foo        inspect program `foo`
  bepeefe-cli obj.o programs foo dump   disassemble it (--src for source)
  bepeefe-cli obj.o maps                list maps
  bepeefe-cli obj.o maps backends       inspect map `backends`
  bepeefe-cli obj.o btf                 list named btf types
  bepeefe-cli obj.o btf task_struct     show a type (--expand for members)
  bepeefe-cli obj.o btf core            list CO-RE relocations";

/// Inspect an eBPF object file.
#[derive(Parser)]
#[command(version, about, after_help = EXAMPLES, arg_required_else_help = true)]
struct Cli {
    /// Path to the eBPF .o file.
    file: PathBuf,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// List or inspect global programs.
    Programs {
        name: Option<String>,
        #[command(subcommand)]
        action: Option<ProgAction>,
    },
    /// List or inspect maps.
    Maps { name: Option<String> },
    /// List or inspect BTF types.
    Btf {
        /// Type name or numeric id.
        query: Option<String>,
        /// Expand nested structs/unions/enums. Pointers are not followed.
        #[arg(short, long)]
        expand: bool,
        /// When listing, include every type.
        #[arg(short, long)]
        all: bool,
        #[command(subcommand)]
        action: Option<BtfAction>,
    },
}

#[derive(Subcommand)]
enum ProgAction {
    /// Disassemble the program's instructions.
    Dump {
        /// Annotate instructions with their source line from .BTF.ext.
        #[arg(long)]
        src: bool,
    },
}

#[derive(Subcommand)]
enum BtfAction {
    /// List CO-RE relocations from .BTF.ext.
    Core,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(&cli.file)?;
    let obj = EbpfObject::from_elf(&bytes)?;

    match cli.command {
        None => overview(&obj),
        Some(Cmd::Programs { name: None, .. }) => programs::list(&obj),
        Some(Cmd::Programs {
            name: Some(n),
            action: None,
        }) => programs::show(&obj, &n)?,
        Some(Cmd::Programs {
            name: Some(n),
            action: Some(ProgAction::Dump { src }),
        }) => programs::disasm(&obj, &n, src)?,
        Some(Cmd::Maps { name: None }) => maps::list(&obj),
        Some(Cmd::Maps { name: Some(n) }) => maps::show(&obj, &n)?,
        Some(Cmd::Btf {
            action: Some(BtfAction::Core),
            ..
        }) => core::list(obj.btf()),
        Some(Cmd::Btf {
            query: None, all, ..
        }) => btf::list(obj.btf(), all),
        Some(Cmd::Btf {
            query: Some(q),
            expand,
            ..
        }) => btf::show(obj.btf(), &q, expand)?,
    }
    Ok(())
}

fn overview(obj: &EbpfObject) {
    println!("license:   {}", obj.license().unwrap_or("?"));
    println!("programs:  {}", obj.programs().count());
    println!("functions: {}", obj.functions().len());
    println!("maps:      {}", obj.maps().len());
    println!("btf types: {}", obj.btf().types.len());
    hint(
        "next:  programs   list programs\n\
         \x20      maps       list maps\n\
         \x20      btf        list btf types\n\
         \x20      (append a name to inspect one)",
    );
}
