/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Internal debug maps, used for SGX to communicate with debugger. We maintain it so that it is in a
 * consistent state any time the process is stopped (any add/delete is an atomic modification of one
 * pointer).
 *
 * The updates are initiated from inside enclave (ocall_debug_add_map() and
 * ocall_debug_delete_map()), but the structure is maintained outside, for easier reading.
 */

#ifndef SGX_RTLD_H
#define SGX_RTLD_H

struct Dwfl_Module;

struct debug_map {
    char* file_name;
    void* load_addr;

    struct debug_map* _Atomic next;

    // See sgx_backtrace.c
    struct Dwfl_Module* module;
};

extern struct debug_map* _Atomic g_debug_map;

int sgx_debug_add_map(const char* file_name, void* load_addr);
int sgx_debug_del_map(void* load_addr);

#endif /* SGX_RTLD_H */
