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

/** One disassembled instruction, as returned by the `disasm` methods on
 *  WasmObject and WasmProgram (a JSON array of these). The second word of a
 *  `LdImm64` is emitted as a row with `insn` null so program counters stay
 *  aligned with the instruction stream. */
export interface DisasmRow {
  pc: number;
  /** Rendered instruction text, null for the trailing word of a `LdImm64`. */
  insn: string | null;
  /** Source location from line_info, null when the pc has no entry. */
  source: DisasmSource | null;
}

export interface DisasmSource {
  line: number;
  col: number;
  /** Source line text pulled from BTF strings. */
  source: string;
}

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
  /** Runtime perf event payload. `pc` is the emitting call instruction and
   *  joins the payload to the PerfEventLayout recorded for that call site.
   *  `fd` is the perf event fd stored in the map slot, not the map's fd. */
  | { PerfEventOutput: { pc: number; fd: number; data: number[] } };

export type VerifierEvent =
  | { Insn: InsnEvent }
  | { BranchEnter: BranchEnterEvent }
  | { BranchDead: BranchDeadEvent }
  | { StatePruned: StatePrunedEvent }
  | { BranchExit: { depth: number } }
  | { CallEnter: CallEnterEvent }
  | { CallExit: CallExitEvent }
  | { PerfEventLayout: PerfEventLayoutEvent }
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

/** How a walk came to exist. On a BranchEnter or BranchDead it is always Branch
 *  or Fallthrough, never Call. `refined` is the register the comparison narrowed
 *  on this arm with its new state, or null when the arm changed nothing.
 *  `fork_pc` is the pc of the jump that spawned the arm: every arm of one
 *  branch, live or dead, shares it, and a StatePruned landing on that jump
 *  carries the same `fork_pc`, which is how it joins to the arms. */
export type WalkOrigin =
  | { Branch: { refined: [number, RegisterState] | null; fork_pc: number } }
  | { Fallthrough: { refined: [number, RegisterState] | null; fork_pc: number } }
  | "Call";

export interface BranchEnterEvent {
  depth: number;
  /** Stable id of this walk. StatePruned events reference it via `matched`. */
  id: number;
  /** For a Branch arm, the jump target. For a Fallthrough arm, the instruction
   *  right after the branch. */
  target_pc: number;
  /** Which arm this is, and the fork pc all its siblings share (see
   *  `WalkOrigin`). */
  kind: WalkOrigin;
}

/** An arm the comparison ruled out. It never entered, so it has no id and no
 *  body, a leaf sibling of the arms that did. `kind` says which side was cut and
 *  carries the same `fork_pc` as those live siblings. */
export interface BranchDeadEvent {
  depth: number;
  target_pc: number;
  kind: WalkOrigin;
}

/** Where walker `matched` sat relative to a StatePruned's `fork_pc`, which tells
 *  you how to reach the continuation without resolving `matched` first. "Jump":
 *  `fork_pc` is a jump `matched` branched at, so the continuation is `matched`'s
 *  arm children, whose `kind.fork_pc` equals this `fork_pc`. "Arm": `fork_pc` is
 *  `matched`'s own entry, so `matched` is itself the arm. */
export type PruneSite = "Jump" | "Arm";

/** This walk stopped because walker `matched` already covered every state
 *  reachable from `fork_pc`. It is not an arm.
 *
 *  Resolve `matched` by indexing every BranchEnter and CallEnter by `id` in one
 *  forward pass. `site` says what its continuation is: for "Jump" it is
 *  `matched`'s arm children sharing this `fork_pc`, one or two of them; for
 *  "Arm" it is `matched` itself and its whole subtree. Either way you never read
 *  this as a single arm. */
export interface StatePrunedEvent {
  depth: number;
  fork_pc: number;
  matched: number;
  site: PruneSite;
}

export interface CallEnterEvent {
  depth: number;
  /** Stable id of this walk. AlreadyVisited prunes reference it via `matched`. */
  id: number;
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

/** The verifier's static view of a bpf_perf_event_output payload: the
 *  stack slots known for the region the data pointer covers. Field
 *  boundaries without types. Recorded while the call is checked, so it
 *  precedes the call's own Insn event. */
export interface PerfEventLayoutEvent {
  depth: number;
  /** pc of the emitting call. Joins this layout to the runtime
   *  PerfEventOutput payloads and the call's Insn event. */
  pc: number;
  map_fd: number;
  /** Payload byte length when known at verification time. */
  size: number | null;
  /** Slots fully inside the payload region. Bytes covered by no slot were
   *  never written on this path. Empty when the data pointer is not an
   *  exact stack pointer or the length is unknown. */
  slots: PayloadSlot[];
}

/** A stack slot inside a perf event payload, as the verifier saw it
 *  written. */
export interface PayloadSlot {
  /** Byte offset within the payload. */
  offset: number;
  size: number;
  state: RegisterState;
  /** pc of the store that wrote this slot. Joins to line_info for the
   *  source location that produced the value. */
  pc: number;
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
