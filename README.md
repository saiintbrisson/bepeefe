# BEPEEFE

BEPEEFE is a toy eBPF VM that doesn't do much, for now, at least. But executes (very simple) code. It supports the base32 [conformance group], divmul32, divmul64, most of the base64, and aims to implement others fully in the Near Future™.

No map support of any kind, no atomic instructions, not all load instructions are implemented yet, doesn't verify shit, and doesn't enforce call or instruction limits.

eBPF is a pretty complex tool with a pretty complex ecosystem. What better way to actually understand it other than implement it yourself, right?

[conformance group]: https://github.com/torvalds/linux/blob/master/Documentation/bpf/standardization/instruction-set.rst#114conformance-groups
