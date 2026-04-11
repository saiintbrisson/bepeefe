// TypeScript declarations for the shapes WasmObject returns, injected
// into the generated bepeefe.d.ts via #[wasm_bindgen(typescript_custom_section)]
// in lib.rs.
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

/** Subset of JSON Schema Draft 7 covering BTF-renderable types, plus
 *  three engine-specific extensions, `pointer`, `union`, and `member`.
 *  Anonymous struct or union members are addressed via the
 *  `_anon_<idx>` protocol key. */
export interface JsonSchema {
  type?: "integer" | "number" | "object" | "array";
  title?: string;
  description?: string;
  minimum?: number;
  maximum?: number;
  /** Either enum variants (`{ const, title }`) or BTF union variants
   *  (full schemas plus a title labelling the member). Use `union`
   *  and `type` to decide which interpretation applies. */
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
}
