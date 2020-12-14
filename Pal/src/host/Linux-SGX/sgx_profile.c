/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * SGX profiling. This code takes samples of running code and writes them out to a perf.data file
 * (see also sgx_perf_data.c).
 */

#ifdef DEBUG

#include <assert.h>
#include <errno.h>
#include <stddef.h>

#include "cpu.h"
#include "sgx_internal.h"
#include "sgx_tls.h"
#include "spinlock.h"
#include "string.h"

#define NSEC_IN_SEC 1000000000
#define NSEC_IN_MSEC 1000000

static spinlock_t g_profile_lock = INIT_SPINLOCK_UNLOCKED;
static struct perf_data* g_perf_data = NULL;

static bool g_profile_enabled = false;
static bool g_profile_with_stack;
static uint64_t g_profile_period_ns;
static char* g_profile_filename = NULL;
static int g_mem_fd = -1;

/* Read memory from inside enclave (using /proc/self/mem). */
static int debug_read(void* dest, void* addr, size_t size) {
    int ret;
    size_t total = 0;

    while (size > 0) {
        ret = INLINE_SYSCALL(pread, 4, g_mem_fd, dest, size, (off_t)addr);

        if (IS_ERR(ret) && ERRNO(ret) == EINTR)
            continue;

        if (IS_ERR(ret))
            break;

        assert(ret > 0);
        assert((unsigned)ret <= size);
        size -= ret;
        dest += ret;
        addr += ret;
        total += ret;
    }
    return total;
}

static int debug_read_all(void* dest, void* addr, size_t size) {
    int ret = debug_read(dest, addr, size);
    if (IS_ERR(ret))
        return ret;
    if ((unsigned)ret < size)
        return -EINVAL;
    return 0;
}

static int get_sgx_gpr(sgx_pal_gpr_t* gpr, void* tcs) {
    int ret;
    uint64_t ossa;
    uint32_t cssa;
    ret = debug_read_all(&ossa, tcs + 16, sizeof(ossa));
    if (ret < 0)
        return ret;
    ret = debug_read_all(&cssa, tcs + 24, sizeof(cssa));
    if (ret < 0)
        return ret;

    void* gpr_addr = (void*)(
        g_pal_enclave.baseaddr
        + ossa + cssa * g_pal_enclave.ssaframesize
        - sizeof(sgx_pal_gpr_t));

    ret = debug_read_all(gpr, gpr_addr, sizeof(*gpr));
    if (ret < 0)
        return ret;

    return 0;
}

int sgx_profile_init(const char* filename, bool with_stack, uint64_t period_ms) {
    int ret;

    assert(!g_profile_enabled);
    assert(g_mem_fd == -1);
    assert(!g_perf_data);

    g_profile_with_stack = with_stack;
    g_profile_period_ns = period_ms * NSEC_IN_MSEC;

    g_profile_filename = strdup(filename);
    if (!g_profile_filename) {
        SGX_DBG(DBG_E, "sgx_profile_init: out of memory\n");
        ret = -ENOMEM;
        goto out;
    }

    ret = INLINE_SYSCALL(open, 3, "/proc/self/mem", O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_init: opening /proc/self/mem failed: %d\n", ERRNO(ret));
        goto out;
    }
    g_mem_fd = ret;

    struct perf_data* pd = pd_open(filename, with_stack);
    if (!pd) {
        SGX_DBG(DBG_E, "sgx_profile_init: pd_open failed\n");
        ret = -EINVAL;
        goto out;
    }
    g_perf_data = pd;
    g_profile_enabled = true;
    return 0;

out:
    if (g_profile_filename) {
        free(g_profile_filename);
        g_profile_filename = NULL;
    }

    if (g_mem_fd > 0) {
        int close_ret = INLINE_SYSCALL(close, 1, g_mem_fd);
        if (IS_ERR(close_ret))
            SGX_DBG(DBG_E, "sgx_profile_init: closing /proc/self/mem failed: %d\n", ERRNO(ret));
        g_mem_fd = -1;
    }
    return ret;
}

void sgx_profile_finish(void) {
    int ret;
    ssize_t size;

    if (!g_profile_enabled)
        return;

    size = pd_close(g_perf_data);
    if (IS_ERR(size))
        SGX_DBG(DBG_E, "sgx_profile_finish: pd_close failed: %d\n", ERRNO((int)size));
    g_perf_data = NULL;

    ret = INLINE_SYSCALL(close, 1, g_mem_fd);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_finish: closing /proc/self/mem failed: %d\n", ERRNO(ret));
    g_mem_fd = -1;

    SGX_DBG(DBG_I, "Profile data written to %s (%lu bytes)\n", g_profile_filename, size);

    free(g_profile_filename);
    g_profile_filename = NULL;

    g_profile_enabled = false;
}

static void sample_simple(void* tcs, pid_t pid, pid_t tid) {
    int ret;
    sgx_pal_gpr_t gpr;

    ret = get_sgx_gpr(&gpr, tcs);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error reading GPR: %d\n", ERRNO(ret));
        return;
    }

    spinlock_lock(&g_profile_lock);
    ret = pd_event_sample_simple(g_perf_data, gpr.rip, pid, tid, g_profile_period_ns);
    spinlock_unlock(&g_profile_lock);

    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error recording sample: %d\n", ERRNO(ret));
    }
}

static void sample_stack(void* tcs, pid_t pid, pid_t tid) {
    int ret;
    sgx_pal_gpr_t gpr;

    ret = get_sgx_gpr(&gpr, tcs);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error reading GPR: %d\n", ERRNO(ret));
        return;
    }

    uint8_t stack[PD_STACK_SIZE];
    size_t stack_size;
    ret = debug_read(stack, (void*)gpr.rsp, sizeof(stack));
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error reading stack: %d\n", ERRNO(ret));
        return;
    }
    stack_size = ret;

    spinlock_lock(&g_profile_lock);
    ret = pd_event_sample_stack(g_perf_data, gpr.rip, pid, tid, g_profile_period_ns, &gpr, stack, stack_size);
    spinlock_unlock(&g_profile_lock);

    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "error recording sample: %d\n", ERRNO(ret));
    }
}

/*
 * Take a sample after an exit from enclave.
 *
 * Use CPU time to record a sample approximately every 'g_profile_period' nanoseconds. Note that we
 * rely on Linux scheduler to generate an AEX event 250 times per second (although other events may
 * cause an AEX to happen more often), so sampling frequency greater than 250 cannot be reliably
 * achieved.
 */
void sgx_profile_sample(void* tcs) {
    int ret;

    if (!g_profile_enabled)
        return;

    // Check current CPU time
    struct timespec ts;
    ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_THREAD_CPUTIME_ID, &ts);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_sample: clock_gettime failed: %d\n", ERRNO(ret));
        return;
    }
    assert((unsigned)ts.tv_sec < (1UL << 63) / NSEC_IN_SEC);
    uint64_t sample_time = ts.tv_sec * NSEC_IN_SEC + ts.tv_nsec;

    // Compare and update last recorded time per thread
    PAL_TCB_URTS* tcb = get_tcb_urts();
    if (tcb->profile_sample_time == 0) {
        tcb->profile_sample_time = sample_time;
        return;
    }

    // Report a sample, if necessary
    if (tcb->profile_sample_time - sample_time >= g_profile_period_ns) {
        tcb->profile_sample_time = sample_time;

        pid_t pid = g_pal_enclave.pal_sec.pid;
        pid_t tid = get_tid_from_tcs(tcs);
        if (IS_ERR(ret)) {
            SGX_DBG(DBG_E, "sgx_profile_sample: could not determine TID: %d\n", ERRNO(ret));
            tid = pid;
        }

        if (g_profile_with_stack)
            sample_stack(tcs, pid, tid);
        else
            sample_simple(tcs, pid, tid);
    }
}



char *realpath(const char *path, char *resolved_path);

void sgx_profile_report_mmap(const char* filename, uint64_t addr, uint64_t len, uint64_t offset) {
    if (!g_profile_enabled)
        return;

    char buf[4096];
    char* path = realpath(filename, buf);
    if (!path)
        return;

    pid_t pid = g_pal_enclave.pal_sec.pid;

    spinlock_lock(&g_profile_lock);
    int ret = pd_event_mmap(g_perf_data, path, pid, addr, len, offset);
    spinlock_unlock(&g_profile_lock);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_report_mmap: pd_event_mmap failed: %d\n", ERRNO(ret));
}

#endif /* DEBUG */
