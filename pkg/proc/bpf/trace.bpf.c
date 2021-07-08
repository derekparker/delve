#include "trace.bpf.h"

SEC("uprobe/dlv_trace")

int uprobe__dlv_trace(struct pt_regs *ctx) {
    struct function_values *arg;
    uint64_t key = ctx->ip;
    unsigned int *m;

    arg = bpf_map_lookup_elem(&arg_map, &key);
    if (!arg) {
        return 1;
    }

    m = bpf_ringbuf_reserve(&events, 0x2f, 0); 
    if (!m) {
        return 1;
    }

    size_t addr = ctx->sp + arg->offset; // + arg->offset + 8;
    long ret = bpf_probe_read_user(m, arg->size & (0x2f - 1), (void *)(addr));
    if (ret < 0) {
        bpf_ringbuf_discard(m, 0);
        return 1;
    }

    *m = *m;

    bpf_ringbuf_submit(m, 0);
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

char _license[] SEC("license") = "GPL";