#include "vmlinux.h"
#include "function_vals.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Ring buffer to handle communication of variable values back to userspace.
struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(max_entries, 42);
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
} arg_map SEC(".maps");
