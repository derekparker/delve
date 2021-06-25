#include "trace.h"

SEC("uprobe/dlv_trace")

int uprobe__dlv_trace(struct pt_regs *ctx) {
    int *ip;
    ip = bpf_ringbuf_reserve(&events, sizeof(int), 0); 
    if (!ip) {
        return 1;
    }
    *ip = ctx->ip;
    bpf_ringbuf_submit(ip, 0);
    return 0;
}