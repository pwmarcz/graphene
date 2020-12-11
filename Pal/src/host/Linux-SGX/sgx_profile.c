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

static void* get_sgx_ip(void* tcs) {
    uint64_t ossa;
    uint32_t cssa;
    if (debug_read(&ossa, tcs + 16, sizeof(ossa)) < 0)
        return NULL;
    if (debug_read(&cssa, tcs + 24, sizeof(cssa)) < 0)
        return NULL;

    void* gpr_addr = (void*)(
        g_pal_enclave.baseaddr
        + ossa + cssa * g_pal_enclave.ssaframesize
        - sizeof(sgx_pal_gpr_t));

    uint64_t rip;
    if (debug_read(&rip, gpr_addr + offsetof(sgx_pal_gpr_t, rip), sizeof(rip)) < 0)
        return NULL;

    return (void*)rip;
}

int sgx_profile_init(const char* file_name) {
    assert(!g_profile_enabled);
    assert(g_mem_fd == -1);
    assert(!g_perf_data);

    int ret = INLINE_SYSCALL(open, 3, "/proc/self/mem", O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "sgx_profile_init: opening /proc/self/mem failed: %d\n", ERRNO(ret));
        goto out;
    }
    g_mem_fd = ret;

    struct perf_data* pd = pd_open(file_name);
    if (!pd) {
        ret = -EINVAL;
        goto out;
    }
    g_perf_data = pd;

    SGX_DBG(DBG_I, "Writing profile data to %s\n", file_name);
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
    if (!g_profile_enabled)
        return;

    pd_close(g_perf_data); // ignore errors (reported in pd_close)
    g_perf_data = NULL;

    int ret = INLINE_SYSCALL(close, 1, g_mem_fd);
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
    if (!g_profile_enabled)
        return;

    // Check current IP in enclave
    void* ip = get_sgx_ip(tcs);
    if (!ip)
        return;

    // Check current CPU time
    struct timespec ts;
    int ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_THREAD_CPUTIME_ID, &ts);
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
        pd_event_sample(g_perf_data, (uint64_t)ip, pid, tid, period);
        spinlock_unlock(&g_profile_lock);
    }
}

#endif /* DEBUG */
