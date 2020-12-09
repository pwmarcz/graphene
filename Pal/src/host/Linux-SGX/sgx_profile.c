/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * SGX profiling. This code maintains a hash map of IP locations encountered inside the enclave,
 * storing counters with elapsed time. The map is written out on program exit, along with map of
 * loaded objects, so that the resulting file can be converted to a report.
 */

#ifdef DEBUG

#include <assert.h>
#include <errno.h>
#include <stddef.h>

#include "cpu.h"
#include "perm.h"
#include "sgx_internal.h"
#include "sgx_tls.h"
#include "spinlock.h"
#include "uthash.h"

#define MAX_FRAMES 32

#define NSEC_IN_SEC 1000000000

// Assume Linux scheduler will normally interrupt the enclave each 4 ms, or 250 times per second
#define MAX_DT (NSEC_IN_SEC / 250)

struct counter {
    UT_hash_handle hh;
    uint64_t value;
    size_t stack_size;
    uint64_t stack[];
};

static spinlock_t g_profile_lock = INIT_SPINLOCK_UNLOCKED;
static struct counter* g_counters = NULL;

static int g_profile_enabled = false;
static int g_profile_all = false;
static int g_mem_fd = -1;

/* Read memory from inside enclave (using /proc/self/mem). */
static int debug_read(void* dest, void* addr, size_t size) {
    ssize_t ret = pread_all(g_mem_fd, dest, size, (off_t)addr);

    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "debug_read: error reading %lu bytes at %p: %d\n", size, addr,
                (int)ERRNO(ret));
        return ret;
    }

    if ((unsigned)ret < size) {
        SGX_DBG(DBG_E, "debug_read: EOF reading %lu bytes at %p\n", size, addr);
        return -EINVAL;
    }
    return 0;
}

static int debug_read_gpr(sgx_pal_gpr_t* gpr, void* tcs) {
    uint64_t ossa;
    uint32_t cssa;
    int ret;

    ret = debug_read(&ossa, tcs + 16, sizeof(ossa));
    if (ret < 0)
        return ret;
    ret = debug_read(&cssa, tcs + 24, sizeof(cssa));
    if (ret < 0)
        return ret;

    void* gpr_addr = (void*)(
        g_pal_enclave.baseaddr
        + ossa + cssa * g_pal_enclave.ssaframesize
        - sizeof(sgx_pal_gpr_t));

    ret = debug_read(gpr, gpr_addr, sizeof(*gpr));
    if (ret < 0)
        return ret;

    return 0;
}

static void gpr_to_pal_context(PAL_CONTEXT* context, sgx_pal_gpr_t* gpr) {
    memset(context, 0, sizeof(*context));
    // Only the registers needed by sgx_backtrace_*.
    context->r8 = gpr->r8;
    context->r9 = gpr->r9;
    context->r10 = gpr->r10;
    context->r11 = gpr->r11;
    context->r12 = gpr->r12;
    context->r13 = gpr->r13;
    context->r14 = gpr->r14;
    context->r15 = gpr->r15;
    context->rdi = gpr->rdi;
    context->rsi = gpr->rsi;
    context->rbp = gpr->rbp;
    context->rbx = gpr->rbx;
    context->rdx = gpr->rdx;
    context->rax = gpr->rax;
    context->rcx = gpr->rcx;
    context->rsp = gpr->rsp;
    context->rip = gpr->rip;
}

static int write_report(int fd) {
    // Write out counters
    struct counter* counter;
    struct counter* tmp;
    HASH_ITER(hh, g_counters, counter, tmp) {
        pal_fdprintf(fd, "counter ");
        for (size_t i = 0; i < counter->stack_size; i++)
            pal_fdprintf(fd, "%lx ", counter->stack[i]);
        pal_fdprintf(fd, "%lu\n", counter->value);
        HASH_DEL(g_counters, counter);
        free(counter);
    }

    // Write out g_debug_map
    struct debug_map* debug_map = (struct debug_map*)g_debug_map;
    while (debug_map) {
        pal_fdprintf(fd, "file %p %s\n", debug_map->load_addr, debug_map->file_name);
        debug_map = (struct debug_map*)debug_map->next;
    }
    return 0;
}

int sgx_profile_init(bool all) {
    assert(!g_profile_enabled);
    assert(g_mem_fd == -1);

    int ret = INLINE_SYSCALL(open, 3, "/proc/self/mem", O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_init: opening /proc/self/mem failed: %d\n", ERRNO(ret));
        return ret;
    }
    g_mem_fd = ret;
    g_profile_enabled = true;
    g_profile_all = all;
    return 0;
}

/*
 * Shut down profiling and write out data to a file.

 * The file will contain two kinds of lines:
 * - "counter 0x<addr> <count>": counter value
 * - "file 0x<addr> <path>": address of shared object loaded inside enclave
 */
void sgx_profile_finish(void) {
    int ret;

    if (!g_profile_enabled)
        return;

    char buf[64];
    if (g_profile_all)
        snprintf(buf, sizeof(buf), "sgx-profile-%d.data", g_pal_enclave.pal_sec.pid);
    else
        snprintf(buf, sizeof(buf), "sgx-profile.data");
    SGX_DBG(DBG_I, "writing profile data to %s\n", buf);

    int fd = INLINE_SYSCALL(open, 3, buf, O_WRONLY | O_TRUNC | O_CREAT, PERM_rw_r__r__);
    if (IS_ERR(fd)) {
        SGX_DBG(DBG_E, "sgx_profile_finish: error opening file: %d\n", -fd);
        goto out;
    }

    ret = write_report(fd);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_finish: error writing report: %d\n", -ret);

    ret = INLINE_SYSCALL(close, 1, fd);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_finish: closing %s failed: %d\n", buf, -ret);

out:
    ret = INLINE_SYSCALL(close, 1, g_mem_fd);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_finish: closing /proc/self/mem failed: %d\n", -ret);
    g_mem_fd = -1;
    g_profile_enabled = false;
}

static ssize_t retrieve_stack(void* tcs, uint64_t* stack, size_t count) {
    int ret;
    sgx_pal_gpr_t gpr;
    PAL_CONTEXT context;

    ret = debug_read_gpr(&gpr, tcs);
    if (ret < 0)
        return ret;
    gpr_to_pal_context(&context, &gpr);
    return sgx_backtrace_get_from(&context, stack, count);
}

/*
 * Update counters after exit from enclave.
 *
 * Note that this uses thread CPU time instead of just increasing the counters by 1. This is because
 * we cannot assume a fixed sampling period (unlike e.g. perf-record). While at least one AEX event
 * should happen every 4 ms (default timer interrupt on modern Linux); AEX events will happen on
 * other interrupts/exceptions as well, such as page faults. Weighing the samples by elapsed time
 * makes sure that we do not inflate the count if AEX events happen more often.
 */
void sgx_profile_sample(void* tcs) {
    if (!g_profile_enabled)
        return;

    uint64_t stack[MAX_FRAMES];
    ssize_t stack_size = retrieve_stack(tcs, stack, MAX_FRAMES);
    if (stack_size <= 0)
        return;

    // Check current CPU time
    struct timespec ts;
    int res = INLINE_SYSCALL(clock_gettime, 2, CLOCK_THREAD_CPUTIME_ID, &ts);
    if (res < 0) {
        SGX_DBG(DBG_E, "sgx_profile_sample: clock_gettime failed: %d\n", res);
        return;
    }
    assert((unsigned)ts.tv_sec < (1UL << 63) / NSEC_IN_SEC);
    uint64_t sample_time = ts.tv_sec * NSEC_IN_SEC + ts.tv_nsec;

    // Compare and update last recorded time per thread
    uint64_t dt = 0;
    PAL_TCB_URTS* tcb = get_tcb_urts();
    if (tcb->profile_sample_time > 0) {
        assert(sample_time >= tcb->profile_sample_time);
        dt = sample_time - tcb->profile_sample_time;

        // Assume that time spent on one sample is never longer than MAX_DT nanoseconds, because of
        // Linux timer interrupt.
        if (dt > MAX_DT)
            dt = MAX_DT;
    }
    tcb->profile_sample_time = sample_time;

    // Increase counters, if necessary
    if (dt > 0) {
        spinlock_lock(&g_profile_lock);

        struct counter* counter;
        HASH_FIND(hh, g_counters, stack, stack_size * sizeof(stack[0]), counter);
        if (counter) {
            counter->value += dt;
        } else {
            counter = malloc(sizeof(*counter) + stack_size * sizeof(stack[0]));
            if (!counter) {
                SGX_DBG(DBG_E, "sgx_profile_sample: out of memory\n");
                spinlock_unlock(&g_profile_lock);
                return;
            }

            counter->value = dt;
            counter->stack_size = stack_size;
            memcpy(counter->stack, stack, stack_size * sizeof(stack[0]));
            HASH_ADD(hh, g_counters, stack, stack_size * sizeof(stack[0]), counter);
        }

        spinlock_unlock(&g_profile_lock);
    }
}

#endif /* DEBUG */
