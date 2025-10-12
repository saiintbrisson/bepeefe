run in="bpf.c" out="bpf.o" program="entry": (build in out)
    cargo r -- {{out}} {{program}}

build in="bpf.c" out="bpf.o":
    clang-19 -O2 -g -o {{out}} -target bpf -c {{in}}

c2asm in="bpf.c" out="bpf.s":
    clang-19 -S -o {{out}} -target bpf -c {{in}}

asm2o in="bpf.s" out="bpf.o":
    llvm-mc-19 -triple bpf -filetype=obj -o {{out}} {{in}}

dump in="bpf.c" out="bpf.o": (build in out)
    llvm-objdump-19 -dr {{out}}
