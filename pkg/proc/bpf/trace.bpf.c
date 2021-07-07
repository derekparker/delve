#include "trace.bpf.h"

SEC("uprobe/dlv_trace")

int uprobe__dlv_trace(struct pt_regs *ctx) {
    struct function_values *args;
    uint64_t key = ctx->ip;
    int *ip;

    ip = bpf_ringbuf_reserve(&events, sizeof(int), 0); 
    if (!ip) {
        return 1;
    }

    args = bpf_map_lookup_elem(&arg_map, &key);
    if (args) {
        *ip = 1;
    } else {
        *ip = 0;
    }

    bpf_ringbuf_submit(ip, 0);

    /*
    int *ip;
    ip = bpf_ringbuf_reserve(&events, sizeof(int), 0); 
    if (!ip) {
        return 1;
    }
    *ip = ctx->ip;
    bpf_ringbuf_submit(ip, 0);
    */
    return 0;
}