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

// Capture up to 2 addresses (saved IP, saved return address)
#define NUM_IPS 2

#define NSEC_IN_SEC 1000000000

// Assume Linux scheduler will normally interrupt the enclave each 4 ms, or 250 times per second
#define MAX_DT (NSEC_IN_SEC / 250)

struct counter {
    uint64_t ips[NUM_IPS];
    uint64_t count;
    UT_hash_handle hh;
};

static spinlock_t g_profile_lock = INIT_SPINLOCK_UNLOCKED;
static struct counter* g_counters = NULL;

static int g_profile_enabled = false;
static int g_profile_all = false;
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

static inline bool is_in_enclave(uintptr_t addr, size_t size) {
    return g_pal_enclave.baseaddr <= addr
        && addr + size < g_pal_enclave.baseaddr + g_pal_enclave.size;
}

static int get_sgx_ips(void* tcs, uint64_t* ips) {
    int ret = 0;

    uint64_t ossa;
    uint32_t cssa;
    if (debug_read(&ossa, tcs + 16, sizeof(ossa)) < 0)
        return ret;
    if (debug_read(&cssa, tcs + 24, sizeof(cssa)) < 0)
        return ret;

    void* gpr_addr = (void*)(
        g_pal_enclave.baseaddr
        + ossa + cssa * g_pal_enclave.ssaframesize
        - sizeof(sgx_pal_gpr_t));

    sgx_pal_gpr_t gpr;
    if (debug_read(&gpr, gpr_addr, sizeof(gpr)) < 0)
        return ret;

    ips[ret++] = gpr.rip;

    /*
     * Try to determine the return addresses, assuming the code uses RBP as frame pointer. Perform the
     * following sanity checks to reduce false positives:
     * - RBP and RSP both in enclave, RSP <= RBP
     * - RBP aligned to 16 bytes
     */
    if (is_in_enclave(gpr.rsp, 16) &&
        is_in_enclave(gpr.rbp, 16) &&
        gpr.rsp <= gpr.rbp &&
        gpr.rbp % 16 == 0) {

        void* prev_addr = (void*)(gpr.rbp + 8);
        uint64_t prev_ip;
        if (debug_read(&prev_ip, prev_addr, sizeof(prev_ip)) < 0)
            return ret;

        if (!is_in_enclave(prev_ip, 1))
            return ret;

        ips[ret++] = prev_ip;
    }

    return ret;
}

static int write_report(int fd) {
    int ret;

    // Write out counters
    struct counter* counter;
    struct counter* tmp;
    HASH_ITER(hh, g_counters, counter, tmp) {
        pal_fdprintf(fd, "counter ");
        for (int i = 0; i < NUM_IPS; i++)
            pal_fdprintf(fd, "0x%lx ", counter->ips[i]);
        pal_fdprintf(fd, "%lu\n", counter->count);
        HASH_DEL(g_counters, counter);
        free(counter);
    }

    // Write out debug_map (unfortunately we have to read it from enclave memory)
    if (g_pal_enclave.debug_map) {
        struct debug_map* _Atomic pmap;
        ret = debug_read(&pmap, g_pal_enclave.debug_map, sizeof(pmap));
        if (IS_ERR(ret))
            return ret;

        while (pmap) {
            struct debug_map map;
            ret = debug_read(&map, pmap, sizeof(map));
            if (IS_ERR(ret))
                return ret;

            pal_fdprintf(fd, "file %p ", map.load_addr);

            // Read file_name byte by byte until we encounter null terminator, and write it out
            char* file_name = map.file_name;
            char c;
            do {
                ret = debug_read(&c, file_name, sizeof(c));
                if (IS_ERR(ret))
                    return ret;
                pal_fdprintf(fd, "%c", c ?: '\n');
                file_name++;
            } while (c);

            pmap = map.next;
        }
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
 * - "counter 0x<addr> 0x<addr> <count>": counter value
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

    // Check current IPs in enclave
    uint64_t ips[NUM_IPS] = {0};
    if (get_sgx_ips(tcs, &ips[0]) == 0)
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
        HASH_FIND(hh, g_counters, &ips, sizeof(ips), counter);
        if (counter) {
            counter->count += dt;
        } else {
            counter = malloc(sizeof(*counter));
            if (!counter) {
                SGX_DBG(DBG_E, "sgx_profile_sample: out of memory\n");
                spinlock_unlock(&g_profile_lock);
                return;
            }

            for (int i = 0; i < NUM_IPS; i++)
                counter->ips[i] = ips[i];
            counter->count = dt;
            HASH_ADD(hh, g_counters, ips, sizeof(counter->ips), counter);
        }

        spinlock_unlock(&g_profile_lock);
    }
}

#endif /* DEBUG */
