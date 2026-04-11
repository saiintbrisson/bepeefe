use std::sync::Arc;

use object::SectionIndex;

use crate::{btf::value::ValueError, object::EbpfProgram};

#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    #[error("malformed BTF section: {0:?}")]
    InvalidBtf(std::io::Error),
    #[error("malformed BTF extension section: {0:?}")]
    InvalidBtfExt(std::io::Error),
    #[error("invalid BTF name offset: {0:?}")]
    InvalidBtfNameOffset(u32),

    #[error(transparent)]
    BtfValidation(#[from] crate::btf::BtfValidationError),

    #[error("deprecated 'maps' section, use '.maps' format instead")]
    DeprecatedMapsSection,

    #[error("invalid map declaration: {0:?}")]
    InvalidMapDeclaration(&'static str),

    #[error("object is missing the .BTF section; BTF is required")]
    MissingBtf,

    #[error("program {0:?} not found in object")]
    ProgramNotFound(String),

    /// Wraps any failure from the underlying ELF parser (`object` crate):
    /// truncated headers, bad section/symbol indices, missing data, etc.
    #[error("ELF object error: {0}")]
    ObjectFile(#[from] object::Error),

    /// A feature we knowingly don't implement yet: unsupported relocation
    /// targets, sign-extension loads, non-text symbol kinds, etc. The
    /// static str names the missing capability.
    #[error("unsupported feature: {0}")]
    Unsupported(&'static str),

    /// A relocation `r_type` we haven't taught the loader to apply.
    #[error("unsupported relocation type {0}")]
    UnsupportedRelocation(u32),

    /// Catch-all for inputs that are structurally invalid in ways that
    /// don't have a more specific variant: wrong BTF kind at a position,
    /// dangling subprogram references, instruction streams that aren't a
    /// multiple of `Insn::WIDTH`, etc.
    #[error("malformed object: {0}")]
    Malformed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("failed to create map {name:?}: {reason}")]
    InvalidMap { name: String, reason: &'static str },

    #[error("duplicate map name {name:?}")]
    DuplicateMap { name: String },

    #[error("failed to write initial data for map {name:?}: {source}")]
    InitialDataWrite {
        name: String,
        #[source]
        source: RuntimeError,
    },

    #[error(
        "map relocation at insn {insn_off} could not be resolved (section {section:?}, offset {sec_offset})"
    )]
    UnresolvedMapRelo {
        insn_off: usize,
        section: SectionIndex,
        sec_offset: usize,
    },

    #[error("relocation points to invalid instruction offset {insn_offset:?}")]
    InvalidInstructionOffset { insn_offset: usize },

    #[error("data relocation targets unknown section {section:?}")]
    UnknownDataReloSection { section: SectionIndex },

    #[error("verification failed: {source}")]
    Verifier {
        #[source]
        source: crate::verifier::VerifierError,
        prog: Arc<EbpfProgram>,
    },
}

impl PrepareError {
    pub fn report(&self) -> String {
        match self {
            PrepareError::Verifier { source, prog } => source.report(prog),
            other => format!("error: {other}\n"),
        }
    }
}

/// Anything that can go wrong while a program is running, or while
/// reading and writing typed maps from the host.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("expected {expected} context argument(s), got {got}")]
    ContextArity { expected: usize, got: usize },

    #[error("map key has wrong size: expected {expected}, got {got}")]
    MapWrongKeySize { expected: usize, got: usize },
    #[error("map value has wrong size: expected {expected}, got {got}")]
    MapWrongValueSize { expected: usize, got: usize },
    #[error("map is full")]
    MapFull,
    #[error("map key not found")]
    MapKeyNotFound,
    #[error("operation not supported by this map type")]
    MapOpUnsupported,

    #[error(transparent)]
    Value(#[from] ValueError),
}
