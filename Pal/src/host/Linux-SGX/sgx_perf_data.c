/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * A library for dumping synthetic perf.data events, for consumption by 'perf report' tool.
 *
 * For more information on the format, see Linux sources:
 *
 * - tools/perf/Documentation/perf.data-file-format.txt
 * - include/uapi/linux/perf_event.h
 * - tools/perf/util/header.h
 *
 * We use the "pipe-mode data" variant, which allows outputting events without going back to update
 * any header structures. The important events are:
 *
 * - PERF_RECORD_HEADER_ATTR: specifies sample_type for PERF_RECORD_SAMPLE events
 * - PERF_RECORD_MMAP: reports mmap of executable region (for later extraction of symbols / call
 *   chain)
 * - PERF_RECORD_SAMPLE: program state (present fields depend on flags in sample_type)
 *
 * For debugging the output, you can use 'perf script -D -i <filename>', which shows a partial parse
 * of the file.
 */

#include <asm/errno.h>
#include <assert.h>
#include <linux/perf_event.h>

#include "perm.h"
#include "sgx_internal.h"

/* Buffering */

#define EV_SIZE 16384
#define BUF_SIZE (1024 * 1024)

/* Internal perf.data file definitions - see linux/tools/perf/util/header.h */

#define PERF_MAGIC 0x32454c4946524550ULL  // "PERFILE2"

struct perf_file_section {
    uint64_t offset;
    uint64_t size;
};

struct perf_file_header {
    uint64_t magic;
    uint64_t size;
    uint64_t attr_size;
    struct perf_file_section        attrs;
    struct perf_file_section        data;
    struct perf_file_section        event_types;
    uint64_t flags[4];
};

struct perf_file_attr {
    struct perf_event_attr attr;
    struct perf_file_section ids;
};

struct perf_data {
    int fd;
    int file_pos;

    // Current event (built using pd_begin .. pd_end)
    size_t ev_pos;
    uint8_t ev[EV_SIZE];

    // Data to be written to file
    size_t buf_pos;
    uint8_t buf[BUF_SIZE];
};

static ssize_t pwrite_all(int fd, const void* buf, size_t count, off_t offset) {
    while (count > 0) {
        ssize_t ret = INLINE_SYSCALL(pwrite, 4, fd, buf, count, offset);
        if (ret == -EINTR)
            continue;
        if (ret < 0)
            return ret;
        count -= ret;
        offset += ret;
        buf += ret;
    }
    return 0;
}

struct perf_data* pd_open(const char* file_name) {
    int fd = INLINE_SYSCALL(open, 3, file_name, O_WRONLY | O_TRUNC | O_CREAT, PERM_rw_r__r__);
    if (fd < 0) {
        SGX_DBG(DBG_E, "pd_open: cannot open %s for writing: %d\n", file_name, -fd);
        return NULL;
    }

    struct perf_data* pd = malloc(sizeof(*pd));
    if (!pd) {
        SGX_DBG(DBG_E, "pd_open: out of memory\n");
        int ret = INLINE_SYSCALL(close, 1, fd);
        if (ret < 0)
            SGX_DBG(DBG_E, "pd_open: close failed: %d\n", ret);
        return NULL;
    }

    pd->fd = fd;
    pd->file_pos = 0;
    pd->ev_pos = 0;

    // Initialize buffer with header and attribute section.
    struct perf_file_attr attr = {
        .attr = {
            .type = PERF_TYPE_SOFTWARE,
            .size = sizeof(attr.attr),
            .sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD,
        },
        .ids = {0},
    };
    struct perf_file_header header = {
        .magic = PERF_MAGIC,
        .size = sizeof(header),
        .attr_size = sizeof(attr.attr),
        .attrs = {
            .offset = sizeof(header),
            .size = sizeof(attr),
        },
        .data = {
            .offset = sizeof(header) + sizeof(attr),
            .size = 0, // updated in pd_flush()
        },
        .event_types = {0},
        .flags = {0},
    };
    memcpy(pd->buf, &header, sizeof(header));
    memcpy(pd->buf + sizeof(header), &attr, sizeof(attr));
    pd->buf_pos = sizeof(header) + sizeof(attr);
    return pd;
};

static int pd_flush(struct perf_data* pd) {
    if (pd->buf_pos == 0)
        return 0;

    // Flush buffer data
    ssize_t ret = pwrite_all(pd->fd, pd->buf, pd->buf_pos, pd->file_pos);
    if (ret < 0) {
        SGX_DBG(DBG_E, "pd_flush: pwrite failed: %d\n", (int)-ret);
        return ret;
    }
    pd->file_pos += pd->buf_pos;
    pd->buf_pos = 0;

    // Update size
    uint64_t size = pd->file_pos - sizeof(struct perf_file_header) - sizeof(struct perf_file_attr);
    ret = pwrite_all(pd->fd, &size, sizeof(size), offsetof(struct perf_file_header, data.size));
    return 0;
}

int pd_close(struct perf_data* pd) {
    int ret;

    ret = pd_flush(pd);
    if (ret < 0)
        return ret;

    ret = INLINE_SYSCALL(close, 1, pd->fd);
    if (ret < 0)
        SGX_DBG(DBG_E, "pd_close: close failed: %d\n", ret);
    free(pd);
    return 0;
}

static void pd_write(struct perf_data* pd, const void* data, size_t size) {
    assert(pd->ev_pos + size < ARRAY_SIZE(pd->ev));
    memcpy(pd->ev + pd->ev_pos, data, size);
    pd->ev_pos += size;
}

static inline void pd_write16(struct perf_data* pd, uint16_t val) {
    pd_write(pd, &val, sizeof(val));
}

static inline void pd_write32(struct perf_data* pd, uint32_t val) {
    pd_write(pd, &val, sizeof(val));
}

static inline void pd_write64(struct perf_data* pd, uint64_t val) {
    pd_write(pd, &val, sizeof(val));
}

/* Begin a new event */
static void pd_begin(struct perf_data* pd, uint32_t type, uint16_t misc) {
    assert(pd->ev_pos == 0);
    // struct perf_event_header { u32 type; u16 misc; u16 size; }
    pd_write32(pd, type);
    pd_write16(pd, misc);
    pd_write16(pd, 0); // updated in pd_end()
}

static int pd_end(struct perf_data* pd) {
    assert(pd->ev_pos > 0);
    // Overwrite size
    uint16_t size = pd->ev_pos;
    memcpy(pd->ev + sizeof(uint32_t) + sizeof(uint16_t), &size, sizeof(size));

    if (pd->buf_pos + pd->ev_pos > ARRAY_SIZE(pd->buf)) {
        int ret = pd_flush(pd);
        if (ret < 0)
            return ret;
    }

    assert(pd->buf_pos + pd->ev_pos <= ARRAY_SIZE(pd->buf));
    memcpy(pd->buf + pd->buf_pos, pd->ev, pd->ev_pos);
    pd->buf_pos += pd->ev_pos;
    pd->ev_pos = 0;
    return 0;
}

int pd_event_mmap(struct perf_data* pd, const char* filename, uint32_t pid, uint64_t addr,
                  uint64_t len, uint64_t pgoff) {
    pd_begin(pd, PERF_RECORD_MMAP, 0);
    pd_write32(pd, pid);
    pd_write32(pd, pid); // tid (set same as pid)
    pd_write64(pd, addr);
    pd_write64(pd, len);
    pd_write64(pd, pgoff);
    pd_write(pd, filename, strlen(filename));
    return pd_end(pd);
}

int pd_event_sample(struct perf_data* pd, uint64_t ip, uint32_t pid,
                    uint32_t tid, uint64_t period) {
    pd_begin(pd, PERF_RECORD_SAMPLE, PERF_RECORD_MISC_USER);
    pd_write64(pd, ip);
    pd_write32(pd, pid);
    pd_write32(pd, tid);
    pd_write64(pd, period);
    return pd_end(pd);
}
