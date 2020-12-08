/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include <asm/errno.h>

#include "sgx_internal.h"
#include "sgx_rtld.h"
#include "spinlock.h"

/* Global debug map. */
struct debug_map* _Atomic g_debug_map = NULL;

/* Lock for modifying g_debug_map on our end. Even though the list can be read at any
 * time, we need to prevent concurrent modification. */
static spinlock_t g_debug_map_lock = INIT_SPINLOCK_UNLOCKED;

static struct debug_map* debug_map_alloc(const char* file_name, void* load_addr) {
    struct debug_map* map;

    if (!(map = malloc(sizeof(*map))))
        return NULL;

    if (!(map->file_name = strdup(file_name))) {
        free(map);
        return NULL;
    }

    map->load_addr = load_addr;
    map->next = NULL;
    return map;
}

static void debug_map_free(struct debug_map* map) {
    free(map->file_name);
    free(map);
}

int sgx_debug_add_map(const char* file_name, void* load_addr) {
    struct debug_map* map = debug_map_alloc(file_name, load_addr);

    if (!map)
        return -ENOMEM;

    spinlock_lock(&g_debug_map_lock);
    map->next = g_debug_map;
    g_debug_map = map;
    spinlock_unlock(&g_debug_map_lock);

    update_debugger();
    sgx_backtrace_update_maps();
    return 0;
}

int sgx_debug_del_map(void* load_addr) {
    spinlock_lock(&g_debug_map_lock);

    struct debug_map* prev = NULL;
    struct debug_map* map = g_debug_map;
    while (map) {
        if (map->load_addr == load_addr)
            break;
        prev = map;
        map = map->next;
    }

    if (!map) {
        spinlock_unlock(&g_debug_map_lock);
        return -EINVAL;
    }

    if (prev == NULL)
        g_debug_map = map->next;
    else
        prev->next = map->next;

    spinlock_unlock(&g_debug_map_lock);

    debug_map_free(map);
    update_debugger();
    sgx_backtrace_update_maps();
    return 0;
}
