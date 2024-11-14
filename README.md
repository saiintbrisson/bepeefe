# BEPEEFE

BEPEEFE is a toy eBPF VM that doesn't do much, for now, at least. But executes (very simple) code. It supports the base32 [conformance group], divmul32, divmul64, most of the base64, and aims to implement others fully in the Near Future™.

Supports array maps for now, but not all operations. You can lookup stuff though, and atomically fetch and add. Maps are generated from parsed BTF information using the libbpf map style.

It isn't nearly 1:1 with actual eBPF execution. For example, stacks have a limited size at the moment, as calculating it would require tracking register usage.

eBPF is a pretty complex tool with a pretty complex ecosystem. What better way to actually understand it other than implement it yourself, right?

You can try it out with:
```shell
$ cargo run -- <ebpf object file> <entry function name>
# or
$ just run examples/bpf/trace_print.c
```

[conformance group]: https://github.com/torvalds/linux/blob/master/Documentation/bpf/standardization/instruction-set.rst#114conformance-groups
