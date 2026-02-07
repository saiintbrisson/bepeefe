# BEPEEFE

BEPEEFE is a toy eBPF VM that doesn't do much. For now, at least. But executes (very simple) code. It supports the base32 [conformance group], divmul32, divmul64, most of the base64, and aims to implement others fully in the Near Future™.

Supports array maps for now, but not all operations. You can lookup stuff though, and atomically fetch and add. Maps are generated from parsed BTF information using the libbpf map style.

eBPF is a pretty complex tool with a pretty complex ecosystem. What better way to actually understand it other than implementing it yourself, right?

You can try it out with:
```shell
$ cargo run --example snake
```

[conformance group]: https://github.com/torvalds/linux/blob/master/Documentation/bpf/standardization/instruction-set.rst#114conformance-groups
