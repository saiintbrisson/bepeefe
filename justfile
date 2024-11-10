run in="bpf.c" out="bpf.o" program="entry": (build in out)
    cargo r -- {{out}} {{program}}

build in="bpf.c" out="bpf.o":
    clang-14 -g -o {{out}} -target bpf -c {{in}}

c2asm in="bpf.c" out="bpf.s":
    clang-14 -S -o {{out}} -target bpf -c {{in}}

compasm in="bpf.s" out="bpf.o":
    llvm-mc-14 -triple bpf -filetype=obj -o {{out}} {{in}}

strip in="bpf.o" out="bpf-stripped.o":
    llvm-objcopy-14 -O binary --only-section=.text {{in}} {{out}}