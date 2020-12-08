/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * File helpers.
 */

#include <asm/errno.h>
#include <assert.h>

#include "sgx_internal.h"

ssize_t pread_all(int fd, void* dest, size_t count, off_t offset) {
    ssize_t total = 0;

    while (count > 0) {
        ssize_t ret = INLINE_SYSCALL(pread, 4, fd, dest, count, offset);

        if (IS_ERR(ret) && ERRNO(ret) == EINTR)
            continue;

        if (IS_ERR(ret))
            return ret;

        if (ret == 0)
            break;

        assert(ret > 0);
        assert((unsigned)ret <= count);
        count -= ret;
        dest += ret;
        offset += ret;
        total += ret;
    }
    return total;
}
