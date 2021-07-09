#include "trace.bpf.h"

int parse_arg(struct pt_regs *ctx, function_parameter_t param) {
    if (param.size > 0x30) {
        return 0;
    }

    unsigned int *m;
    m = bpf_ringbuf_reserve(&events, 0x30, 0); 
    if (!m) {
        return 1;
    }

    // param = args->params[0];
    size_t addr = ctx->sp + param.offset; // + arg->offset + 8;
    long ret = bpf_probe_read_user(m, param.size, (void *)(addr));
    if (ret < 0) {
        bpf_ringbuf_discard(m, 0);
        return 1;
    }

    bpf_ringbuf_submit(m, 0);

    return 1;
}

SEC("uprobe/dlv_trace")
int uprobe__dlv_trace(struct pt_regs *ctx) {
    struct function_parameter_list *args;
    function_parameter_t param;
    uint64_t key = ctx->ip;

    args = bpf_map_lookup_elem(&arg_map, &key);
    if (!args) {
        return 1;
    }

    // Since we cannot loop in eBPF programs let's take adavantage of the
    // fact that in C switch cases will pass through automatically.
    switch (args->n_parameters) {
        case 8:
            parse_arg(ctx, args->params[7]);
        case 7:
            parse_arg(ctx, args->params[6]);
        case 6:
            parse_arg(ctx, args->params[5]);
        case 5:
            parse_arg(ctx, args->params[4]);
        case 4:
            parse_arg(ctx, args->params[3]);
        case 3:
            parse_arg(ctx, args->params[2]);
        case 2:
            parse_arg(ctx, args->params[1]);
        case 1:
            parse_arg(ctx, args->params[0]);
    }

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