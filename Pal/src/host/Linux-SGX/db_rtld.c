/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include "elf-x86_64.h"
#include "elf/elf.h"
#include "pal_linux.h"
#include "pal_rtld.h"

void _DkDebugAddMap(struct link_map* map) {
    int ret = ocall_debug_add_map(map->l_name, (void*)map->l_addr);
    if (ret < 0)
        SGX_DBG(DBG_E, "_DkDebugAddMap: ocall_debug_add_map failed: %d\n", ret);
}

void _DkDebugDelMap(struct link_map* map) {
    int ret = ocall_debug_del_map((void*)map->l_addr);
    if (ret < 0)
        SGX_DBG(DBG_E, "_DkDebugAddMap: ocall_debug_del_map failed: %d\n", ret);
}

void setup_pal_map(struct link_map* pal_map) {
    const ElfW(Ehdr)* header = (void*)pal_map->l_addr;

    pal_map->l_real_ld = pal_map->l_ld = (void*)elf_machine_dynamic();
    pal_map->l_type    = OBJECT_RTLD;
    pal_map->l_entry   = header->e_entry;
    pal_map->l_phdr    = (void*)(pal_map->l_addr + header->e_phoff);
    pal_map->l_phnum   = header->e_phnum;
    setup_elf_hash(pal_map);

    pal_map->l_prev = pal_map->l_next = NULL;
    g_loaded_maps = pal_map;

    int ret = ocall_debug_add_map(pal_map->l_name, (void*)pal_map->l_addr);
    if (ret < 0)
        SGX_DBG(DBG_E, "setup_pal_map: ocall_debug_add_map failed: %d\n", ret);
}
