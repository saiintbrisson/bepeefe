# BEPEEFE

BEPEEFE is a userspace eBPF VM written in Rust. Load an eBPF object file, verify the program, and execute it.

What does it do?

- ISA supports most of the base32 and base64 groups. ALU32/ALU64, conditional and unconditional jumps, calls, load and store operations, LD_IMM64, subprograms.
  - Immediate stores, sign-extending loads, atomics for or/and/xor/xchg are missing.
- ELF loading, relocations, `.maps` support, `.BTF` and `.BTF.ext` parsing, `.bss`/`.data`/`.rodata` auto-generated as array maps, program and sub-program discovery, limited section-based [attach point parsing](./src/bpf_prog.rs).
  - Only `R_BPF_64_32` and `R_BPF_64_64` relocations are supported (as of now).
- BTF and BTF extension parsing, validation, datasec resolution. 
- Small maps coverage: `ARRAY`, `HASH`, `STACK`, `PERF_EVENT_ARRAY`.
  - Most maps are not implemented. I'd like to have `SOCKMAP`, `RINGBUF`, `PERCPU_*`, and `LRU_*` next.
  - You can serialize and deserialize map keys and values with [`serde`](./src/btf/value.rs).
  - `PERF_EVENT_ARRAY`: in its current form, it doesn't behave like the kernel map does, it holds an FD as its value and emits a [`perf event`](./src/capture.rs).
- Many fundamental helpers are implemented, particularly around map manipulation, probe reads, prandom, CPU ID, PID/TGID, COMM, KTIME.
  - The current set allows for small, basic programs, like tcpstates to run, but it's miles away from supporting more complicated, useful programs.
- There is a verifier, but it covers a much smaller set of programs compared to the kernel's. This is by far the most complicated piece of the project.
  - For instance, it supports the basic pointer types (ctx, stack, map, map value or null, refined map value, partial packet/meta/packet end), but doesn't refine like the kernel does. First, because the kernel verifier is huge, second, our scalar values do not carry a `tnum`, and instead I opted for a simpler stride-based range, that allows for basic shifting support, but fails to track values through masks, ors, etc.

### Try it!

If you have [`bpf-linker`](https://github.com/aya-rs/bpf-linker) installed on a macOS or Linux system, you should be able to compile one of the Rust-based [`rust-examples`](./rust-examples):

```shell
$ cargo run -p rust-examples --example snake
```

Otherwise, try running one of the [`c-examples`](./c-examples), which come pre-built:

```shell
$ cargo run -p c-examples --example snake
```

## Why?

eBPF is vast and complex, and the obscurity around it was overwhelming. I first wrote the ISA interpreter, but that covered just a small fraction of what makes it useful. Next step was working on a few helpers, then BTF, maps, relocations, verifier, etc.

I now have a decently good understanding of the inner workings of eBPF and how the kernel interacts with it. So mission accomplished. Like it did for me, I hope this project helps more people learn about a fascinating, and considerably obscure/undocumented, technology.

## In practice

First, an `EbpfObject` is built from an ELF object, it carries map declarations, programs and BTF. Programs are loaded on demand. Call `EbpfObject::load_prog(program_name)` to load its instructions and those of its subprograms, and resolve relocations.

```rust
let obj = EbpfObject::from_elf(PROGRAM)?;
let prog: EbpfProgram = obj.load_prog("handle_set_state")?;
```

Your program needs preparation in order to run. The `Vm` struct holds maps, and different programs can access shared maps. It assigns FDs and IDs to maps, and the program needs this information to rewrite relos targeting them. `Vm::prepare` will find all maps declared in your object, create and assign the metadata necessary, then resolve the relocations with the newly created FDs. Finally, it passes the program through the verifier, checking all possible branches the code takes and tracking memory accesses, helper parameters, and more.

```rust
let vm = Vm::new();
let prog: Arc<PreparedProgram> = vm.prepare(prog, MapReuseStrategy::None, VerifierConfig::default())?;
```

> `MapReuseStrategy` is either `None` or `MatchByName`. The former fails if a new map declaration conflicts with an existing map, regardless of type. The latter searches for existing maps with the same name. Libbpf's `pinning` attribute on maps overrides this behavior.

Great! Your program passed the verifier, it's safe to execute, all helper calls, memory reads and writes, context accesses are valid. Now onto running it! `bepeefe`'s API allows building the execution image, host env, and interacting with registers:

```rust
struct EventSink;
impl Capture for EventSink {
    fn record(&self, e: CapEvent<'_>) { /* ... */ }
}
let sink = Arc::new(EventSink);

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug, serde::Serialize))]
enum TcpState {
    Established = 1,
    SynSent = 2,
    FinWait1 = 4,
    #[default]
    Close = 7,
}

#[repr(C)]
#[cfg_attr(not(target_arch = "bpf"), derive(serde::Serialize))]
struct InetSockSetState {
    // ...
    #[cfg_attr(not(target_arch = "bpf"), serde(serialize_with = "skaddr_as_u64"))]
    skaddr: *const c_void,
    oldstate: TcpState,
    newstate: TcpState,
    // ...
}

let transitions = &[
    (TcpState::Close,       TcpState::SynSent,     0),             
    (TcpState::SynSent,     TcpState::Established, 30_000_000), 
    (TcpState::Established, TcpState::FinWait1,    1_500_000_000), 
    (TcpState::FinWait1,    TcpState::Close,       1_550_000_000),
];

for &(old, new, time) in transitions {
    let ctx = InetSockSetState {
        skaddr: 0x0, oldstate: old, newstate: new,
        family: AF_INET, protocol: IPPROTO_TCP,
        /* ... */
    };
    // The task that triggered this invocation rides along with the
    // context. The clock, RNG, and probe memory live on the VM instead,
    // so we advance the world between runs.
    vm.world().ktime_ns = time;
    let task = Task::new(1234, 4321, "curl").unwrap();
    let image = prog.build_image(&[ctx])?.from_task(task);

    let _r0 = prog.run(image, Some(sink.clone()));
}
```

A lot is happening here. The first few lines declare an event sink to capture events emitted by the VM, all `printk`s and `perf_event_output`s are routed there, we print to terminal here.

In this example, we emulate a scenario where a socket goes through 4 state transitions. The for loop initializes an `InetSockSetState`, equivalent to `struct trace_event_raw_inet_sock_set_state`, we use it to build an image for the program to execute on. Types can implement `Serialize`, and the engine uses BTF information to encode the binary representation expected by the program. Up to 5 parameters can be provided to a function, though most eBPF programs only use one.

The values a kernel would naturally provide to helpers split in two. The triggering task (pid, tgid, comm) belongs to a single invocation, so it attaches to the image with `from_task`. The clock, the current CPU, the RNG, and the kernel and user memory regions read by `bpf_probe_read_*` belong to the machine, so they live in the VM's `World` and persist across runs. You reach the world through `vm.world()` and mutate it in place between invocations, which is how the RNG keeps advancing and the clock keeps the time you last set.

`PreparedProgram::run` creates a new CPU and runs it to completion, returning the r0 value when `exit` is called.

[Check the full example.](./rust-examples/tcpstates.rs)

## In depth

This project covers a tiny bit of the complexity in eBPF, and even then it's already considerably complex. Let's walk through it.

### Loading

As mentioned above, program loading is split in two. The [object file](./src/object.rs) parsing reads BTF and its extension, maps declarations and collects all function signatures (name, arguments, return type). Program loading walks through all relocations recursively, building a single view of all the program instructions, and subprograms it calls. The VM preparation does the rest, fixing up map accesses.

#### Object parsing

BTF parsing is the first step. eBPF programs carry information about structs, maps and functions they interact with, located in sections `.BTF` and `.BTF.ext`. Types, names, lines are all listed here, and we have to do some pre-processing to make it useful:
* Datasec entries sizes and offsets are left blank by Clang, it's the linker's or libbpf's (or any loader) job to populate them, finding the target for `R_BPF_64_64` relocations depends on this (see [`fixup_btf_datasecs`](./src/object.rs)).
* We then validate that BTF has no dangling type IDs (like struct members or pointers that refer to invalid types), and that fields expected to have size, have, indeed, a size (see [`Btf::validate`](./src/btf.rs)).

With BTF directory built, we parse the maps. The legacy `maps` section from libbpf is rejected. The `.maps` section has a corresponding `datasec` entry in BTF, that carries a list of `var`s, that in turn point to `struct`s. This is where the map declaration lives. Each attribute in the map declaration lives as a BTF member in that struct. Take for example the following:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(value, __u32);
    __uint(max_entries, 128);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} things SEC(".maps");
```

All `__type` and `__uint` really do is expand to:

```c
struct {
    int (*type)[2]; /* BPF_MAP_TYPE_ARRAY=2 */
    __u32 *value;
    int (*max_entries)[128];
    int (*pinning)[1]; /* LIBBPF_PIN_BY_NAME=1 */
} things SEC(".maps");
```

All members are pointers, so we first resolve that indirection. For `type`, `max_entries`, `map_flags`, `numa_node`, or any other attribute that takes a _value_, they are generated as an array type where the value is the dimension, so `pinning=1` (enabled by name) results in a BTF type describing an array with 1 element. As for the others, like `key` and `value`, they are the type that the pointer indirection resolves to (see [`parse_maps`](./src/object.rs)).

Finally, we collect all function signatures using `.BTF.ext`'s `func_info` list. They resolve to a BTF `func` type and include the instruction offset at which the function begins within its section.

Consider reading more about BTF before proceeding [here](https://github.com/torvalds/linux/blob/master/Documentation/bpf/btf.rst).

#### Program loading

With the object parsed, BTF validated and known functions collected, it's time to load the requested program. We allow loading global functions, static functions are only accepted as subprograms.

For each program, we need to resolve what and where its instructions are. If an object has multiple programs, we will only load the instructions necessary to run the single requested program (and subprogs). This is done by iterating over all instructions, finding relocations and resolving them, iterating through those, until all are covered. If the instruction at which a relocation is found is a subprogram call (`BPF_JMP | BPF_CALL | BPF_K` with `src reg=1`), we extend the loaded instructions with the ones resulting from that subprogram.

After those are loaded, we do a pass over all relocations again. This time, actually rewriting instructions with the correct offsets for the loaded subprograms:
* `R_BPF_64_32`: rewrite immediate so that it becomes `(target offset - current offset) / 8 + imm / 8 - 1`. Minus one because PC is incremented past `call` before the jump actually occurs.
* `R_BPF_64_64` and `opcode=LD_IMM64`: if no offset is present for the target, this is a relocation pointing to a map, so we store that and use it later, after maps are created in the VM. Otherwise, we bail.

We also collect line information from the BTF extension, which lets us link source code lines to instructions.

### BTF

Parsing was described above, but I think it's worth talking about the `Value` type, which implements Serialize/Deserialize, particularly useful for encoding to/from JSON. And a custom serialize/deserialize impl allows converting any Rust type into a `Value`. Interacting with maps or building the context parameters becomes trivial:

```rust
#[repr(u8)]
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "bpf"), derive(serde::Deserialize))]
enum RenderEventType {
    Clear = 0,
    Snake = 1,
    Food = 2,
}

#[repr(C)]
#[cfg_attr(not(target_arch = "bpf"), derive(serde::Deserialize))]
struct RenderEvent {
    x: u8,
    y: u8,
    ty: RenderEventType,
}

decl_map!(render_events {
    r#type: BPF_MAP_TYPE_STACK,
    value: RenderEvent,
    max_entries: 1024,
});

let mut map = vm.map("render_events").unwrap();
if let Some(ev) = map.pop::<RenderEvent>().unwrap() {
  match ev.ty {
      RenderEventType::Clear => todo!(),
      RenderEventType::Snake => todo!(),
      RenderEventType::Food => todo!(),
  }
}
```

And the same applies to building the context. If your program is also written in Rust, you can re-use the types freely. Check out the [snake game](./rust-examples/snake.rs). Under the hood, `Value` uses the BTF information attached to each function argument or map key/value to understand if the input provided by the user is compatible with what the program expects.

For anon fields in a struct or union, the field name is `_anon_<idx>`, where `idx` is the index for that field. There's also a BTF builder to help with tests and missing BTF information.

### VM

The memory is not flat. The VM does not hold a single memory slice accessed by all programs, instead, different memory regions exist. Maps manage their own memory, each program execution (through [`Cpu`](./src/vm/cpu.rs)) owns its own stack allocation, user and kernel memories are nothing but an `Arc<[u8]>` in the VM's [`World`](./src/vm/world.rs). What we do instead is tag the pointers when initializing the registers (see [`TaggedPtr`](./src/vm/ptr.rs)), and the CPU is responsible for decoding the register and routing the read/write to the correct place.

All events emitted by the program are piped through the `Capture` trait in the [practical example](#in-practice). Those are prints (via the `printk` helper), perf output events (which carry an FD attached to the event, corresponding to the FD in the `PERF_EVENT_ARRAY` map), and verifier warnings and trace, useful for understanding how the verifier sees your program.

#### Preparing

Running a program requires a `Vm` struct because the map data has to live somewhere. When preparing a program to load (see [`Vm::prepare`](./src/vm/prepare.rs)), maps are effectively created in the VM, or matched against existing ones. `.bss`, `.rodata`, `.data` sections are treated as BPF Array maps, and initialized with the section data if present.

After FDs are assigned, the prepare function does one last pass rewriting the LD IMM64 instructions with the actual map FD and setting the source register to `BPF_PSEUDO_MAP_FD`.

Then the verifier runs. Once that's done, a `PreparedProgram` is created, linked to that VM.

#### Helpers

Helpers are implemented through a [`BpfHelper`](./src/vm/helpers.rs) trait, responsible for both the runtime execution and the verifier rules. Helpers read per-invocation identity from the [`Task`](./src/vm/task.rs) on the image and machine state (clock, CPU, RNG, probe memory) from the VM's [`World`](./src/vm/world.rs).

KFuncs are not supported yet.

### Verifier

The kernel verifier is a very complex piece of engineering. And the implementation here doesn't begin to scratch the surface of what the complete verifier does. I began working on it with a simple goal in mind: be able to verify a snake game. This was complex enough to cover many simple eBPF programs.

It does the basics (which is already decently complex): track register states, written stack, call stack, helper calling hygiene, memory access validation (based on BTF types), register refinement. I wouldn't say it does it well, though.

For example, scalar tracking is a big part of the kernel verifier. It uses something called `tnum`, which tracks what bits can and cannot be set at any given time. Very clever, also very complex to implement. So I came up with a much simpler way to deal with scalars. Apart from min/max tracking like the kernel does, each scalar contains a `stride`, the distance between numbers in the min/max range. This is enough to enable shift operations over scalar registers, and was enough for the snake game. As I would come to find out, it is enough for a good amount of eBPF programs (see [`ScalarRange`](./src/verifier.rs)).

Helper call hygiene is enforced for all implemented helpers. The verifier also emits warnings in a few specific cases. Currently, the only one is when a tracepoint program accesses the `trace_entry` struct, which in the real kernel gets overwritten with a pointer to a `pt_regs` struct.

Refinement is implemented for most relevant jump conditions, but not all (see [`decide_branch`](./src/verifier.rs)). Refining a value means that, for example, given a register with an unknown scalar, an `if unsigned reg < 64` means that in that branch the register will be in the range 0..64, and we use this information to enforce memory access rules. Another refinement happens around map lookups, where the verifier figures out from a null check whether the result is null or a valid pointer: `if reg != 0` means that in that branch, the register holds a valid pointer to a map element.

This verifier isn't complete, and probably never will be. It lacks many features (e.g. pruning), isn't well tested (if at all, apart from refinement branches), and is (or should be) way more restrictive than the kernel version.
