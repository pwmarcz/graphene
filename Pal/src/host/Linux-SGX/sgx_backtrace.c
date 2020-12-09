/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Backtrace support, using libdwfl library.
 *
 * The library documentation exists mostly in the header file, see:
 *    https://sourceware.org/git/?p=elfutils.git;a=blob;f=libdwfl/libdwfl.h
 *
 * You can also refer to an example program:
 *    https://sourceware.org/git/?p=elfutils.git;a=blob;f=tests/backtrace-data.c
 */

#include <asm/errno.h>

#include <elfutils/libdwfl.h>

#include "pal.h"
#include "sgx_internal.h"
#include "sgx_rtld.h"
#include "sigset.h"
#include "spinlock.h"

/* Current libdwfl session. We keep one per process. */
static Dwfl* g_dwfl = NULL;
/* Context to use for cb_set_initial_registers. We use a global variable instead of thread_arg,
 * because thread_arg is set once per session (in dwfl_attach_state(). */
static PAL_CONTEXT* g_dwfl_context = NULL;
/* Lock for g_dwfl and g_dwfl_context. */
static spinlock_t g_dwfl_lock = INIT_SPINLOCK_UNLOCKED;

static int g_mem_fd = -1;

static bool cb_memory_read(Dwfl* dwfl, Dwarf_Addr addr, Dwarf_Word* result, void* dwfl_arg) {
    __UNUSED(dwfl);
    __UNUSED(dwfl_arg);
    int ret = pread_all(g_mem_fd, result, sizeof(*result), (off_t)addr);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error reading memory at 0x%lu: %d\n", addr, ERRNO(ret));
        return false;
    }
    if ((unsigned)ret < sizeof(*result)) {
        SGX_DBG(DBG_E, "EOF reading memory at 0x%lu: %d\n", addr, ERRNO(ret));
        return false;
    }

    return true;
}

/*
 * Callback for enumerating threads. Because we don't need to process multiple threads at the same
 * time, we pretend there is just one thread, with TID equal to main process PID.
 */
static pid_t cb_next_thread(Dwfl* dwfl, void* dwfl_arg, void** thread_argp) {
    __UNUSED(dwfl);
    __UNUSED(dwfl_arg);

    // If *thread_argp has already been set, report no further threads
    if (*thread_argp != NULL)
        return 0;

    // Set *thread_argp to a dummy non-null value
    *thread_argp = thread_argp;
    return dwfl_pid(dwfl);
}

static bool cb_set_initial_registers(Dwfl_Thread* thread, void* thread_arg) {
    __UNUSED(thread_arg);

    PAL_CONTEXT* context = g_dwfl_context;
    assert(context);

    Dwarf_Word dwarf_regs[17];
    dwarf_regs[0] = context->rax;
    dwarf_regs[1] = context->rdx;
    dwarf_regs[2] = context->rcx;
    dwarf_regs[3] = context->rbx;
    dwarf_regs[4] = context->rsi;
    dwarf_regs[5] = context->rdi;
    dwarf_regs[6] = context->rbp;
    dwarf_regs[7] = context->rsp;
    dwarf_regs[8] = context->r8;
    dwarf_regs[9] = context->r9;
    dwarf_regs[10] = context->r10;
    dwarf_regs[11] = context->r11;
    dwarf_regs[12] = context->r12;
    dwarf_regs[13] = context->r13;
    dwarf_regs[14] = context->r14;
    dwarf_regs[15] = context->r15;
    dwarf_regs[16] = context->rip;

    if (!dwfl_thread_state_registers(thread, 0, 17, dwarf_regs)) {
        SGX_DBG(DBG_E, "dwfl_thread_state_registers() failed: %s\n", dwfl_errmsg(-1));
        return false;
    }

    return true;
}

static int cb_print_frame(Dwfl_Frame* state, void* arg) {
    int* nump = arg;
    int num = (*nump)++;

    // Determine PC. libdwlf documentation says:
    // "Typically you need to substract 1 from *PC if *ACTIVATION is false to safely
    // find function of the caller."
    Dwarf_Addr pc, pc_adjusted;
    bool is_activation;
    if (!dwfl_frame_pc(state, &pc, &is_activation)) {
        SGX_DBG(DBG_E, "dwfl_frame_pc() failed: %s\n", dwfl_errmsg(-1));
        return DWARF_CB_ABORT;
    }
    pc_adjusted = pc - (is_activation ? 0 : 1);

    Dwfl* dwfl = dwfl_thread_dwfl(dwfl_frame_thread(state));
    Dwfl_Module* module = dwfl_addrmodule(dwfl, pc_adjusted);

    if (module) {
        Dwarf_Addr module_start;
        const char* module_name = dwfl_module_info(
            module,
            /*userdata=*/NULL,
            /*start=*/&module_start,
            /*end=*/NULL,
            /*dwbias=*/NULL,
            /*symbias=*/NULL,
            /*mainfile=*/NULL,
            /*debugfile=*/NULL);
        const char* sym_name = dwfl_module_addrname(module, pc_adjusted) ?: "??";

        pal_printf("#%d 0x%lx %s (%s: 0x%lx)\n",
                   num, pc, sym_name,
                   module_name,
                   pc - module_start);

    } else {
        pal_printf("#%d 0x%lx ??\n", num, pc);
    }

    return DWARF_CB_OK;
}

struct cb_get_frame_data {
    uint64_t* stack;
    size_t count;
    size_t index;
};

static int cb_get_frame(Dwfl_Frame* state, void* arg) {
    struct cb_get_frame_data* data = arg;
    if (data->index >= data->count)
        return DWARF_CB_ABORT;

    Dwarf_Addr pc;
    if (!dwfl_frame_pc(state, &pc, NULL)) {
        SGX_DBG(DBG_E, "dwfl_frame_pc() failed: %s\n", dwfl_errmsg(-1));
        return DWARF_CB_ABORT;
    }
    data->stack[data->index++] = pc;
    return DWARF_CB_OK;
}

static const Dwfl_Callbacks g_dwfl_callbacks = {
    .find_debuginfo = NULL, //dwfl_standard_find_debuginfo,
    .debuginfo_path = NULL,
    .section_address = dwfl_offline_section_address,
    .find_elf = dwfl_linux_proc_find_elf,
};

static const Dwfl_Thread_Callbacks g_dwfl_thread_callbacks = {
    .next_thread = cb_next_thread,
    .get_thread = NULL,
    .memory_read = cb_memory_read,
    .set_initial_registers = cb_set_initial_registers,
    .detach = NULL,
    .thread_detach = NULL,
};

static const char* basename(const char* path) {
    const char* prev = path;
    while (*path) {
        if (*path == '/')
            prev = path + 1;
        path++;
    }
    return prev;
}

int sgx_backtrace_init(void) {
    int ret;

    assert(!g_dwfl);
    assert(g_mem_fd == -1);

    ret = INLINE_SYSCALL(open, 3, "/proc/self/mem", O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_backtrace_init: opening /proc/self/mem failed: %d\n", ERRNO(ret));
        return ret;
    }
    g_mem_fd = ret;

    g_dwfl = dwfl_begin(&g_dwfl_callbacks);
    if (!g_dwfl) {
        SGX_DBG(DBG_E, "dwfl_begin() failed: %s\n", dwfl_errmsg(-1));
        goto out;
    }

    pid_t pid = g_pal_enclave.pal_sec.pid;

    sgx_backtrace_update_maps();

    if (!dwfl_attach_state(g_dwfl, EM_NONE, pid, &g_dwfl_thread_callbacks, NULL)) {
        SGX_DBG(DBG_E, "dwfl_attach_state() failed: %s\n", dwfl_errmsg(-1));
        goto out;
    }

    return 0;

out:
    // clean up
    sgx_backtrace_finish();
    return -EINVAL;
}

void sgx_backtrace_finish(void) {
    if (g_dwfl) {
        dwfl_end(g_dwfl);
        g_dwfl = NULL;
    }

    if (g_mem_fd) {
        int ret = INLINE_SYSCALL(close, 1, g_mem_fd);
        if (IS_ERR(ret))
            SGX_DBG(DBG_E, "sgx_backtrace_init: closing /proc/self/mem failed: %d\n", ERRNO(ret));
        g_mem_fd = -1;
    }
}

/*
 * Reload module map. libdwfl will not allow us to add/remove a single map, but wants us to report a
 * full list (between dwfl_report_begin() .. dwfl_report_end()) calls, and will garbage-collect the
 * modules not added.
 */
void sgx_backtrace_update_maps(void) {
    if (!g_dwfl)
        return;

    pid_t pid = g_pal_enclave.pal_sec.pid;

    spinlock_lock(&g_dwfl_lock);

    dwfl_report_begin(g_dwfl);
    // Update outer PAL maps (from /proc/self/maps).
    if (dwfl_linux_proc_report(g_dwfl, pid) != 0) {
        SGX_DBG(DBG_E, "dwfl_linux_proc_report() failed: %s\n", dwfl_errmsg(-1));
    }

    // Update inner maps (from the g_debug_map structure).
    struct debug_map* debug_map = (struct debug_map*)g_debug_map;
    while (debug_map) {
        if (debug_map->module) {
            // The module is already loaded, we must call dwfl_report_module (with the right start
            // and end parameters) to prevent it from unloading.
            GElf_Addr start, end;
            const char* module_name = dwfl_module_info(
                debug_map->module,
                /*userdata=*/NULL,
                /*start=*/&start,
                /*end=*/&end,
                /*dwbias=*/NULL,
                /*symbias=*/NULL,
                /*mainfile=*/NULL,
                /*debugfile=*/NULL);
            dwfl_report_module(g_dwfl, module_name, start, end);
        } else {
            const char* module_name = basename(debug_map->file_name);
            Dwfl_Module* module = dwfl_report_elf(
                g_dwfl,
                /*name=*/module_name,
                /*file_name=*/debug_map->file_name,
                /*fd=*/-1,
                /*base=*/(GElf_Addr)debug_map->load_addr,
                /*add_p_vaddr=*/false);

            if (!module)
                SGX_DBG(DBG_E, "dwfl_report_module() failed: %s\n", dwfl_errmsg(-1));
            debug_map->module = module;
        }
        debug_map = (struct debug_map*)debug_map->next;
    }

    if (dwfl_report_end(g_dwfl, NULL, NULL) != 0)
        SGX_DBG(DBG_E, "dwfl_report_end() failed: %s\n", dwfl_errmsg(-1));

    spinlock_unlock(&g_dwfl_lock);
}

void sgx_backtrace_print_from(PAL_CONTEXT* context) {
    if (!g_dwfl)
        return;

    pid_t pid = g_pal_enclave.pal_sec.pid;

    spinlock_lock(&g_dwfl_lock);
    g_dwfl_context = context;
    int num = 0;
    if (dwfl_getthread_frames(g_dwfl, pid, cb_print_frame, &num) != 0) {
        SGX_DBG(DBG_E, "dwfl_getthread_frames() failed: %s\n", dwfl_errmsg(-1));
    }
    g_dwfl_context = NULL;
    spinlock_unlock(&g_dwfl_lock);
}

void sgx_backtrace_print(void) {
    if (!g_dwfl)
        return;

    PAL_CONTEXT context = {0};
    __asm__(
        "leaq (%%rip), %%rax\n"
        "movq %%rax, %0\n"
        "movq %%rbp, %1\n"
        "movq %%rsp, %2\n"
        : "=m"(context.rip), "=m"(context.rbp), "=m"(context.rsp)
        :: "rax");
    sgx_backtrace_print_from(&context);
}

ssize_t sgx_backtrace_get_from(PAL_CONTEXT* context, uint64_t* stack, size_t count) {
    pid_t pid = g_pal_enclave.pal_sec.pid;
    struct cb_get_frame_data data = {
        .stack = stack,
        .count = count,
        .index = 0,
    };

    spinlock_lock(&g_dwfl_lock);
    g_dwfl_context = context;
    if (dwfl_getthread_frames(g_dwfl, pid, cb_get_frame, &data) != 0) {
        /*
         * If data.index == data.count, we aborted because of filling the stack array.
         *
         * Otherwise, there has been an error: report it, but return the number of successfully
         * retrieved frames.
         */
        if (data.index < data.count)
            SGX_DBG(DBG_E, "dwfl_getthread_frames() failed: %s\n", dwfl_errmsg(-1));
    }
    g_dwfl_context = NULL;
    spinlock_unlock(&g_dwfl_lock);

    return data.index;
}
