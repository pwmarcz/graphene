
#include <asm/errno.h>

#include <elfutils/libdwfl.h>

#include "pal.h"
#include "sgx_internal.h"
#include "sgx_rtld.h"
#include "sigset.h"

// https://sourceware.org/git/?p=elfutils.git;a=blob;f=libdwfl/libdwfl.h
// https://sourceware.org/git/?p=elfutils.git;a=blob;f=tests/backtrace-data.c

// Used by dwfl_standard_find_debuginfo
static char* g_debuginfo_path;

static int g_mem_fd = -1;

/* Read memory from inside enclave (using /proc/self/mem). */
static int debug_read(void* dest, void* addr, size_t size) {
    int ret;
    size_t cur_size = size;
    void* cur_dest = dest;
    void* cur_addr = addr;

    while (cur_size > 0) {
        ret = INLINE_SYSCALL(pread, 4, g_mem_fd, cur_dest, cur_size, (off_t)cur_addr);

        if (IS_ERR(ret) && ERRNO(ret) == EINTR)
            continue;

        if (IS_ERR(ret)) {
            SGX_DBG(DBG_E, "debug_read: error reading %lu bytes at %p: %d\n", size, addr, ERRNO(ret));
            return ret;
        }

        if (ret == 0) {
            SGX_DBG(DBG_E, "debug_read: EOF reading %lu bytes at %p\n", size, addr);
            return -EINVAL;
        }

        assert(ret > 0);
        assert((unsigned)ret <= cur_size);
        cur_size -= ret;
        cur_dest += ret;
        cur_addr += ret;
    }
    return 0;
}

static bool memory_read(Dwfl* dwfl, Dwarf_Addr addr, Dwarf_Word* result, void* dwfl_arg) {
    __UNUSED(dwfl);
    __UNUSED(dwfl_arg);
    if (debug_read(result, (void*)addr, sizeof(*result)) < 0)
        return false;
    return true;
}

static pid_t next_thread(Dwfl* dwfl, void* dwfl_arg, void** thread_argp) {
    __UNUSED(dwfl);

    if (*thread_argp != NULL)
        return 0;
    *thread_argp = dwfl_arg;
    return dwfl_pid(dwfl);
}

static bool set_initial_registers(Dwfl_Thread* thread, void* thread_arg) {
    PAL_CONTEXT* pc = thread_arg;

    Dwarf_Word dwarf_regs[17];
    dwarf_regs[0] = pc->rax;
    dwarf_regs[1] = pc->rdx;
    dwarf_regs[2] = pc->rcx;
    dwarf_regs[3] = pc->rbx;
    dwarf_regs[4] = pc->rsi;
    dwarf_regs[5] = pc->rdi;
    dwarf_regs[6] = pc->rbp;
    dwarf_regs[7] = pc->rsp;
    dwarf_regs[8] = pc->r8;
    dwarf_regs[9] = pc->r9;
    dwarf_regs[10] = pc->r10;
    dwarf_regs[11] = pc->r11;
    dwarf_regs[12] = pc->r12;
    dwarf_regs[13] = pc->r13;
    dwarf_regs[14] = pc->r14;
    dwarf_regs[15] = pc->r15;
    dwarf_regs[16] = pc->rip;

    pal_printf("RIP = %p\n", (void*)pc->rip);

    if (!dwfl_thread_state_registers(thread, 0, 17, dwarf_regs)) {
        SGX_DBG(DBG_E, "dwfl_thread_state_registers() failed: %s\n", dwfl_errmsg(-1));
        return false;
    }

    return true;
}

static int print_frame(Dwfl_Frame* state, void* arg) {
    __UNUSED(arg);

    Dwarf_Addr pc;
    bool isactivation;
    if (!dwfl_frame_pc(state, &pc, &isactivation)) {
        SGX_DBG(DBG_E, "dwfl_frame_pc() failed: %s\n", dwfl_errmsg(-1));
        return 1;
    }
    Dwarf_Addr pc_adjusted = pc - (isactivation ? 0 : 1);

    Dwfl* dwfl = dwfl_thread_dwfl(dwfl_frame_thread(state));
    Dwfl_Module* mod = dwfl_addrmodule(dwfl, pc_adjusted);

    const char* symname = mod ? dwfl_module_addrname(mod, pc_adjusted) : "(unknown)";
    pal_printf("frame: %p %s\n", (void*)pc_adjusted, symname);

    return DWARF_CB_OK;
}


void print_backtrace(PAL_CONTEXT* pc) {
    int ret = INLINE_SYSCALL(open, 3, "/proc/self/mem", O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_init: opening /proc/self/mem failed: %d\n", ERRNO(ret));
        return;
    }
    g_mem_fd = ret;


    pid_t pid = g_pal_enclave.pal_sec.pid;
    const Dwfl_Callbacks callbacks = {
        .find_debuginfo = dwfl_standard_find_debuginfo,
        .debuginfo_path = &g_debuginfo_path,
        .section_address = dwfl_offline_section_address,
        .find_elf = dwfl_linux_proc_find_elf,
    };

    const Dwfl_Thread_Callbacks thread_callbacks = {
        .next_thread = next_thread,
        .get_thread = NULL,
        .memory_read = memory_read,
        .set_initial_registers = set_initial_registers,
        .detach = NULL,
        .thread_detach = NULL,
    };

    Dwfl *dwfl = dwfl_begin(&callbacks);
    if (!dwfl) {
        SGX_DBG(DBG_E, "dwfl_begin() failed: %s\n", dwfl_errmsg(-1));
        return;
    }

    if (dwfl_linux_proc_report(dwfl, pid) != 0) {
        SGX_DBG(DBG_E, "dwfl_linux_proc_report() failed: %s\n", dwfl_errmsg(-1));
        goto out;
    }

    struct debug_map* debug_map = (struct debug_map*)g_debug_map;
    while (debug_map) {
        Dwfl_Module* mod = dwfl_report_elf(
            dwfl, debug_map->file_name,
            debug_map->file_name, -1, (GElf_Addr)debug_map->load_addr, false);

        if (!mod) {
            SGX_DBG(DBG_E, "dwfl_report_module() failed: %s\n", dwfl_errmsg(-1));
            // continue
        }
        debug_map = (struct debug_map*)debug_map->next;
    }


    if (!dwfl_attach_state(dwfl, EM_NONE, pid, &thread_callbacks, pc)) {
        SGX_DBG(DBG_E, "dwfl_attach_state() failed: %s\n", dwfl_errmsg(-1));
        goto out;
    }

    if (dwfl_getthread_frames(dwfl, pid, print_frame, NULL) != 0) {
        SGX_DBG(DBG_E, "dwfl_getthread_frames() failed: %s\n", dwfl_errmsg(-1));
        goto out;
    }

out:
    dwfl_end(dwfl);
}
