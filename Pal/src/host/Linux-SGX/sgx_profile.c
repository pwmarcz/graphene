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

#define NSEC_IN_SEC 1000000000

// Assume Linux scheduler will normally interrupt the enclave each 4 ms, or 250 times per second
#define MAX_DT (NSEC_IN_SEC / 250)

static spinlock_t g_profile_lock = INIT_SPINLOCK_UNLOCKED;
static struct perf_data* g_perf_data = NULL;

static int g_profile_enabled = false;
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

int sgx_profile_init(const char* filename) {
    assert(!g_profile_enabled);
    assert(g_mem_fd == -1);
    assert(!g_perf_data);

    int ret = INLINE_SYSCALL(open, 3, "/proc/self/mem", O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_init: opening /proc/self/mem failed: %d\n", ERRNO(ret));
        goto out;
    }
    g_mem_fd = ret;

    struct perf_data* pd = pd_open(filename);
    if (!pd) {
        SGX_DBG(DBG_E, "sgx_profile_init: pd_open failed\n");
        ret = -EINVAL;
        goto out;
    }
    g_perf_data = pd;

    SGX_DBG(DBG_I, "Writing profile data to %s\n", filename);
    g_profile_enabled = true;
    return 0;

out:
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

    if (!g_profile_enabled)
        return;

    ret = pd_close(g_perf_data);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_finish: pd_close failed: %d\n", ERRNO(ret));
    g_perf_data = NULL;

    ret = INLINE_SYSCALL(close, 1, g_mem_fd);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_finish: closing /proc/self/mem failed: %d\n", ERRNO(ret));
    g_mem_fd = -1;

    g_profile_enabled = false;
}

/*
 * Take a sample after an exit from enclave.
 *
 * Note that this uses thread CPU time for period. This is because we cannot assume a fixed sampling
 * period (unlike e.g. perf-record). While at least one AEX event should happen every 4 ms (default
 * timer interrupt on modern Linux); AEX events will happen on other interrupts/exceptions as well,
 * such as page faults. Weighing the samples by elapsed time makes sure that we do not inflate the
 * count if AEX events happen more often.
 */
void sgx_profile_sample(void* tcs) {
    int ret;

    if (!g_profile_enabled)
        return;

    sgx_pal_gpr_t gpr;
    ret = get_sgx_gpr(&gpr, tcs);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_sample: error reading GPR: %d\n", ERRNO(ret));
        return;
    }
    uint8_t stack[PD_STACK_SIZE];
    size_t stack_size;
    ret = debug_read(stack, (void*)gpr.rsp, sizeof(stack));
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_sample: error reading stack: %d\n", ERRNO(ret));
        return;
    }
    stack_size = ret;

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
    uint64_t period = 0;
    PAL_TCB_URTS* tcb = get_tcb_urts();
    if (tcb->profile_sample_time > 0) {
        assert(sample_time >= tcb->profile_sample_time);
        period = sample_time - tcb->profile_sample_time;

        // Assume that time spent on one sample is never longer than MAX_DT nanoseconds, because of
        // Linux timer interrupt.
        if (period > MAX_DT)
            period = MAX_DT;
    }
    tcb->profile_sample_time = sample_time;

    // Report a sample, if necessary
    if (period > 0) {
        pid_t pid = g_pal_enclave.pal_sec.pid;
        pid_t tid = get_tid_from_tcs(tcs);
        if (IS_ERR(ret)) {
            SGX_DBG(DBG_E, "sgx_profile_sample: could not determine TID: %d\n", ERRNO(ret));
            tid = pid;
        }

        spinlock_lock(&g_profile_lock);
        ret = pd_event_sample(g_perf_data, gpr.rip, pid, tid, period, &gpr, stack, stack_size);
        spinlock_unlock(&g_profile_lock);
        if (IS_ERR(ret))
            SGX_DBG(DBG_E, "sgx_profile_sample: pd_event_sample failed: %d\n", ERRNO(ret));
    }
}

void sgx_profile_report_mmap(const char* filename, uint64_t addr, uint64_t len, uint64_t offset) {
    if (!g_profile_enabled)
        return;

    pid_t pid = g_pal_enclave.pal_sec.pid;

    spinlock_lock(&g_profile_lock);
    int ret = pd_event_mmap(g_perf_data, filename, pid, addr, len, offset);
    spinlock_unlock(&g_profile_lock);
    if (IS_ERR(ret))
        SGX_DBG(DBG_E, "sgx_profile_report_mmap: pd_event_mmap failed: %d\n", ERRNO(ret));
}

#endif /* DEBUG */
