// TypeScript declarations for the shapes WasmObject returns and the
// capture event stream, injected into the generated bepeefe.d.ts via
// #[wasm_bindgen(typescript_custom_section)] in lib.rs.
//
// Each interface has a serde::Serialize counterpart in this crate.
// This file is the source of truth for the JS surface. The Rust
// struct is the source of truth for the wire payload. Keep them in sync.
//
// Engine BTF types (BtfType, BtfKind, etc.) deliberately don't appear
// here. Consumers work off pre-computed schemas instead.

export interface ProgramSchema {
  name: string;
  section?: string;
  hook?: HookInfo;
  params: ParamSchema[];
}

export interface ParamSchema {
  name: string;
  /** Opaque BTF id, used as a handle for follow-up calls like type_schema. */
  type_id: number;
  schema: JsonSchema;
}

/** Subset of the engine's Hook surfaced to JS. */
export interface HookInfo {
  raw: string;
}

export interface MapSchema {
  name: string;
  map_type?: number;
  max_entries?: number;
  key_size?: number;
  value_size?: number;
  /** Opaque BTF id handles, same role as ParamSchema.type_id. */
  key_type_id?: number;
  value_type_id?: number;
  key?: JsonSchema;
  value?: JsonSchema;
}

/** A named, sized type entry returned by browseable_types. The label
 *  is pre-formatted ("struct sock", "u32", ...) so JS callers never
 *  need to walk BTF strings. */
export interface BrowseEntry {
  type_id: number;
  label: string;
  kind: "struct" | "union" | "enum" | "int";
  size: number;
}

/** A CO-RE relocation from .BTF.ext, with its access spec resolved against
 *  the BTF type graph. Returned by core_relos. */
export interface CoreRelo {
  section: string;
  /** Instruction index the relocation patches. */
  insn: number;
  /** libbpf relocation kind, e.g. "field_byte_offset", "enumval_value". */
  kind: string;
  /** BTF id the relocation is anchored to. */
  type_id: number;
  /** Pre-formatted label for `type_id`, e.g. "struct sock". */
  type_label?: string;
  /** Raw access spec as stored in BTF, e.g. "0:1:0". */
  access: string;
  /** Rendered target: ".field.sub" for field access, "::VARIANT" for an enum
   *  value. Absent for whole-type relocations. */
  path?: string;
  /** Field-access hops from the root type to the leaf, each naming a member
   *  (or "[i]" array element) and the type it reaches, so a caller can drill
   *  in with type_schema. Present for field relocations. */
  hops?: CoreReloHop[];
  /** Byte offset of the leaf field from the root. Present for field relocations. */
  byte_offset?: number;
  /** Selected variant name. Present for enumval relocations. */
  variant?: string;
}

export interface CoreReloHop {
  name: string;
  type_id: number;
}

/** One event streamed to the WasmCapture callback. The callback receives a
 *  JSON string that parses into this shape. Serde's externally tagged
 *  encoding applies throughout: unit variants are plain strings, data
 *  variants are single-key objects. */
export type CaptureEvent =
  | { Print: string }
  | { Verifier: VerifierEvent }
  | { PerfEventOutput: { fd: number; data: number[] } };

export type VerifierEvent =
  | { Insn: InsnEvent }
  | { BranchEnter: BranchEnterEvent }
  | { BranchExit: { depth: number } }
  | { CallEnter: CallEnterEvent }
  | { CallExit: CallExitEvent }
  | { Warning: { pc: number; message: string } };

export interface InsnEvent {
  depth: number;
  pc: number;
  /** Registers whose state the check consulted, as register indices.
   *  Calls over-approximate to r1 through r5. */
  read: number[];
  /** Registers the instruction wrote, paired with their new state.
   *  Empty for walk-spawning jumps, whose refinements arrive on the
   *  arms' BranchEnter events. */
  written: [number, RegisterState][];
}

export type BranchDecision = "Both" | "SkipBranch" | "SkipFallthrough";

export interface BranchEnterEvent {
  depth: number;
  target_pc: number;
  /** Verdict for the jump that spawned this arm. "Both" means a sibling
   *  arm is also walked. */
  decision: BranchDecision;
  /** Register the comparison refined on this arm, with its new state.
   *  The rest of the arm's registers match the parent walk. */
  refined: [number, RegisterState] | null;
}

export interface CallEnterEvent {
  depth: number;
  target_pc: number;
  /** Subprogram name, empty when unknown. */
  name: string;
  /** BTF id of the subprogram's Func type, usable with type_schema. */
  btf_id: number | null;
  /** Callee registers on entry, r1 onwards carry the arguments. */
  registers: RegisterState[];
}

export interface CallExitEvent {
  depth: number;
  /** State the call returns in r0. The caller's r1 through r5 always
   *  become "Uninit" after a call, that is left implicit. */
  r0: RegisterState;
}

/** Verifier view of a register. */
export type RegisterState =
  | "Uninit"
  | "PtrToPacketEnd"
  | { Scalar: Scalar }
  | { PtrToCtx: { btf_id: number; offset: ScalarRange; size: number } }
  | { PtrToPacket: { id: number; offset: ScalarRange } }
  | { PtrToPacketMeta: { id: number; offset: ScalarRange } }
  | { PtrToStack: { offset: ScalarRange } }
  | { PtrToMap: { map_fd: number } }
  | { PtrToMapValue: { map_fd: number; offset: ScalarRange } }
  | { PtrToMapValueOrNull: { map_fd: number } };

export type Scalar = "Unknown" | { U32: ScalarRange } | { U64: ScalarRange };

/** Inclusive value range with a stride between representable points.
 *  U64 ranges above 2^53 lose precision crossing JSON. */
export interface ScalarRange {
  min: number;
  max: number;
  stride: number;
}

/** Subset of JSON Schema Draft 7 covering BTF-renderable types, plus
 *  three engine-specific extensions, `pointer`, `union`, and `member`.
 *  Anonymous struct or union members are addressed via the
 *  `_anon_<idx>` protocol key. */
export interface JsonSchema {
  /** BTF id of the concrete type after stripping pointers and typedefs.
   *  A handle for follow-up `type_schema` calls and for linking shared or
   *  recursive types back to their definition. */
  type_id?: number;
  type?: "boolean" | "integer" | "number" | "object" | "array";
  /** BTF type name, preferring the typedef alias when the type is reached
   *  through one. Present on every named type, including ints and enums. */
  title?: string;
  description?: string;
  minimum?: number;
  maximum?: number;
  /** Enum constants when entries carry `const`, otherwise BTF union variants
   *  (full schemas plus a title labelling the member). `union` marks the
   *  union case. */
  oneOf?: Array<JsonSchema & { const?: number; title: string }>;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  minItems?: number;
  maxItems?: number;
  /** Pointer indirections before the concrete type. 1 means `*`, 2 means `**`. */
  pointer?: number;
  /** Marks an object schema as a BTF union. `oneOf` then lists variants. */
  union?: boolean;
  /** For union variants only, the real BTF member name. Omitted for
   *  anonymous members. */
  member?: string;
  /** Bit offset of this member from the start of its parent struct or union. */
  bit_offset?: number;
  /** Width in bits of a bitfield member. Absent on plain members. */
  bits?: number;
}
