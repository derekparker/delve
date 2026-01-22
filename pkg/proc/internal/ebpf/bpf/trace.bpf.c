#include "include/trace.bpf.h"

#define SLICE_KIND 23
#define STRING_KIND 24

// saved_regs_t holds register values from pt_regs.
// The eBPF verifier is conservative about ctx (pt_regs) accesses: after certain
// operations (map lookups, ringbuf operations, BPF_CORE_READ), it marks ctx as
// "potentially modified" and rejects further field accesses. To work around this,
// we save all register values at the very start, before any other operations.
typedef struct {
    u64 ax, dx, cx, bx, si, di, bp, sp;
    u64 r8, r9, r10, r11, r12, r13, r14, r15;
    u64 ip;
} saved_regs_t;

__always_inline
void save_registers(struct pt_regs *ctx, saved_regs_t *regs) {
    regs->ax = ctx->ax;
    regs->dx = ctx->dx;
    regs->cx = ctx->cx;
    regs->bx = ctx->bx;
    regs->si = ctx->si;
    regs->di = ctx->di;
    regs->bp = ctx->bp;
    regs->sp = ctx->sp;
    regs->r8 = ctx->r8;
    regs->r9 = ctx->r9;
    regs->r10 = ctx->r10;
    regs->r11 = ctx->r11;
    regs->r12 = ctx->r12;
    regs->r13 = ctx->r13;
    regs->r14 = ctx->r14;
    regs->r15 = ctx->r15;
    regs->ip = ctx->ip;
}

// parse_slice_param will parse a slice parameter. A slice header contains
// [ptr:8][len:8][cap:8]. We capture the header metadata and read the actual
// slice data into param->deref_val.
__always_inline
int parse_slice_param(function_parameter_t *param) {
    u64 slice_len, slice_cap;
    size_t slice_ptr;

    __builtin_memcpy(&slice_ptr, param->val, sizeof(slice_ptr));
    __builtin_memcpy(&slice_len, param->val + sizeof(slice_ptr), sizeof(slice_len));
    __builtin_memcpy(&slice_cap, param->val + sizeof(slice_ptr) + sizeof(slice_len), sizeof(slice_cap));

    param->daddr = slice_ptr;

    // Read the actual slice data from user memory.
    // We need to be careful about the size limit - deref_val is only 0x30 bytes.
    if (slice_ptr != 0 && param->element_size > 0) {
        size_t bytes_to_read = slice_len * param->element_size;
        if (bytes_to_read > 0x30) {
            bytes_to_read = 0x30;
        }
        int ret = bpf_probe_read_user(&param->deref_val, bytes_to_read, (void*)(slice_ptr));
        if (ret < 0) {
            return 1;
        }
    }

    return 0;
}

// parse_string_param will parse a string parameter. The parsed value of the string
// will be put into param->deref_val. This function expects the string struct
// which contains a pointer to the string and the length of the string to have
// already been read from memory and passed in as param->val.
__always_inline
int parse_string_param(function_parameter_t *param) {
    u64 str_len;
    size_t str_addr;

    __builtin_memcpy(&str_addr, param->val, sizeof(str_addr));
    __builtin_memcpy(&str_len, param->val + sizeof(str_addr), sizeof(str_len));
    param->daddr = str_addr;

    if (str_addr != 0) {
        if (str_len > 0x30) {
            str_len = 0x30;
        }
        int ret = bpf_probe_read_user(&param->deref_val, str_len, (void *)(str_addr));
        if (ret < 0) {
            return 1;
        }
    }
    return 0;
}

__always_inline
int parse_param_stack(u64 sp, function_parameter_t *param) {
    long ret;
    size_t addr = sp + param->offset;
    ret = bpf_probe_read_user(&param->val, param->size, (void *)(addr));
    if (ret < 0) {
        return 1;
    }
    return 0;
}

__always_inline
void get_value_from_register(saved_regs_t *regs, void *dest, int reg_num) {
    u64 val;
    switch (reg_num) {
    case 0:  val = regs->ax; break;
    case 1:  val = regs->dx; break;
    case 2:  val = regs->cx; break;
    case 3:  val = regs->bx; break;
    case 4:  val = regs->si; break;
    case 5:  val = regs->di; break;
    case 6:  val = regs->bp; break;
    case 7:  val = regs->sp; break;
    case 8:  val = regs->r8; break;
    case 9:  val = regs->r9; break;
    case 10: val = regs->r10; break;
    case 11: val = regs->r11; break;
    case 12: val = regs->r12; break;
    case 13: val = regs->r13; break;
    case 14: val = regs->r14; break;
    case 15: val = regs->r15; break;
    default: val = 0; break;
    }
    __builtin_memcpy(dest, &val, sizeof(val));
}

__always_inline
int parse_param_registers(saved_regs_t *regs, function_parameter_t *param) {
    switch (param->n_pieces) {
    case 6:
        get_value_from_register(regs, param->val+40, param->reg_nums[5]);
    case 5:
        get_value_from_register(regs, param->val+32, param->reg_nums[4]);
    case 4:
        get_value_from_register(regs, param->val+24, param->reg_nums[3]);
    case 3:
        get_value_from_register(regs, param->val+16, param->reg_nums[2]);
    case 2:
        get_value_from_register(regs, param->val+8, param->reg_nums[1]);
    case 1:
        get_value_from_register(regs, param->val, param->reg_nums[0]);
    }
    return 0;
}

__always_inline
int parse_param(saved_regs_t *regs, function_parameter_t *param) {
    if (param->size > 0x30) {
        return 0;
    }

    // Parse the initial value of the parameter.
    // If the parameter is a basic type, we will be finished here.
    // If the parameter is a more complex type such as a string or
    // a slice we will need some further processing below.
    int ret = 0;
    if (param->in_reg) {
        ret = parse_param_registers(regs, param);
    } else {
        ret = parse_param_stack(regs->sp, param);
    }
    if (ret != 0) {
        return ret;
    }

    switch (param->kind) {
        case SLICE_KIND:
            return parse_slice_param(param);
        case STRING_KIND:
            return parse_string_param(param);
    }

    return 0;
}

__always_inline
int get_goroutine_id(function_parameter_list_t *parsed_args) {
    struct task_struct *task;
    size_t g_addr;
    __u64  goid;

    // Get the current task.
    task = (struct task_struct *)bpf_get_current_task();
    // Get the Goroutine ID which is stored in thread local storage.
    bpf_probe_read_user(&g_addr, sizeof(void *), (void*)(BPF_CORE_READ(task, thread.fsbase)+parsed_args->g_addr_offset));
    bpf_probe_read_user(&goid, sizeof(void *), (void*)(g_addr+parsed_args->goid_offset));
    parsed_args->goroutine_id = goid;

    return 1;
}

__always_inline
void parse_params(saved_regs_t *regs, unsigned int n_params, function_parameter_t params[6]) {
    // Since we cannot loop in eBPF programs let's take advantage of the
    // fact that in C switch cases will pass through automatically.
    switch (n_params) {
    case 6:
        parse_param(regs, &params[5]);
    case 5:
        parse_param(regs, &params[4]);
    case 4:
        parse_param(regs, &params[3]);
    case 3:
        parse_param(regs, &params[2]);
    case 2:
        parse_param(regs, &params[1]);
    case 1:
        parse_param(regs, &params[0]);
    }
}

SEC("uprobe/dlv_trace")
int uprobe__dlv_trace(struct pt_regs *ctx) {
    function_parameter_list_t *args;
    function_parameter_list_t *parsed_args;
    saved_regs_t regs;

    // Save all register values first. The eBPF verifier marks ctx as "potentially
    // modified" after certain operations (even non-ctx operations like map lookups),
    // so we must capture all values before doing anything else.
    save_registers(ctx, &regs);

    args = bpf_map_lookup_elem(&arg_map, &regs.ip);
    if (!args) {
        return 1;
    }

    parsed_args = bpf_ringbuf_reserve(&events, sizeof(function_parameter_list_t), 0);
    if (!parsed_args) {
        return 1;
    }

    // Initialize the parsed_args struct.
    parsed_args->goid_offset = args->goid_offset;
    parsed_args->g_addr_offset = args->g_addr_offset;
    parsed_args->goroutine_id = args->goroutine_id;
    parsed_args->fn_addr = args->fn_addr;
    parsed_args->n_parameters = args->n_parameters;
    parsed_args->n_ret_parameters = args->n_ret_parameters;
    parsed_args->is_ret = args->is_ret;
    __builtin_memcpy(parsed_args->params, args->params, sizeof(args->params));
    __builtin_memcpy(parsed_args->ret_params, args->ret_params, sizeof(args->ret_params));

    if (!args->is_ret) {
        // In uprobe at function entry.

        // Parse input parameters.
        parse_params(&regs, args->n_parameters, parsed_args->params);
    } else {
        // We are now stopped at the RET instruction for this function.

        // Parse output parameters.
        parse_params(&regs, args->n_ret_parameters, parsed_args->ret_params);
    }

    if (!get_goroutine_id(parsed_args)) {
        bpf_ringbuf_discard(parsed_args, 0);
        return 1;
    }

    bpf_ringbuf_submit(parsed_args, BPF_RB_FORCE_WAKEUP);

    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
