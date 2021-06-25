#!/bin/bash
set -e

if [ ! $(which clang) ]; then
    echo "You must install clang before compiling the bpf program."
    exit 1
fi

clang \
    -I /usr/src/kernels/5.12.11-300.fc34.x86_64/tools/lib \
    -I /usr/src/kernels/5.12.11-300.fc34.x86_64/tools/bpf/resolve_btfids/libbpf \
    -g -O2 \
    -c \
    -target bpf \
    -o trace.o \
    trace.bpf.c