#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

// Utility macros
#define LOWEST_ADDR     0x00000000
#define HIGHEST_ADDR    0xffffffff
#define MAGIC_NUMBER    0x12345678
#define FOOTER_BYTES    4
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static struct m61_statistics global_stats = {
    .nactive = 0,                           // # active allocations
    .active_size = 0,                       // # bytes in active allocations
    .ntotal = 0,                            // # total allocations
    .total_size = 0,                        // # bytes in total allocations
    .nfail = 0,                             // # failed allocation attempts
    .fail_size = 0,                         // # bytes in failed alloc attempts
    .heap_min = (char *) 0xfffffffffff,    // smallest allocated addr
    .heap_max = (char *) 0x00000000000     // largest allocated addr
};

static meta_t* meta_list = NULL;

// List functions
meta_t* metalist_find(void *payload_ptr) {
    meta_t *curr = meta_list;
    while (curr != NULL && curr->payload_addr != payload_ptr) {
        curr = curr->next;
    }
    return curr;
}

void metalist_insert(meta_t *node) {
    if (!meta_list) {
        meta_list = node;
        return;
    }

    meta_t *curr = meta_list;
    while (curr->next != NULL) curr = curr->next;
    curr->next = node;
}

void metalist_remove(void *payload_ptr) {
    if (!meta_list) {
        // ERROR: cannot remove from empty list
        return;
    }

    if (meta_list->payload_addr == payload_ptr) {
        meta_list = meta_list->next;
        return;
    }

    meta_t *prev = NULL;
    meta_t *curr = meta_list;

    while (curr != NULL && curr->payload_addr != payload_ptr) {
        prev = curr;
        curr = curr->next;
    }

    if (!curr) {
        // Error: cannot find in the list
        return;
    }

    prev->next = curr->next;
}

/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.

    // Overflow check
    if (sz > sz + 1) {
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return NULL;
    }

    size_t meta_size = sizeof(meta_t);
    size_t required_size = meta_size + sz + FOOTER_BYTES;
    void *malloc_ptr = base_malloc(required_size);

    if (!malloc_ptr) {
        // Handle base_malloc failure
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return malloc_ptr;
    }

    meta_t *meta_ptr = (meta_t *) malloc_ptr;
    void *payload_ptr = (void *) ((char *) (malloc_ptr + meta_size));

    // Initialise meta data
    meta_ptr->payload_sz = sz;
    meta_ptr->payload_addr = payload_ptr;
    meta_ptr->file = file;
    meta_ptr->line = line;
    meta_ptr->next = NULL;

    metalist_insert(meta_ptr);

    // Initialise footer
    int *footer = (int *) ((char *) (payload_ptr + sz));
    *footer = MAGIC_NUMBER;

    update_statistics_malloc(payload_ptr, sz);
    return payload_ptr;
} 

void update_statistics_malloc(void *payload_ptr, size_t payload_sz) {
    global_stats.nactive++;
    global_stats.active_size += payload_sz;
    global_stats.ntotal++;
    global_stats.total_size += payload_sz;

    char *min_addr = (char *) payload_ptr;
    char *max_addr = (char *) (payload_ptr + payload_sz);

    global_stats.heap_min = MIN(global_stats.heap_min, min_addr);
    global_stats.heap_max = MAX(global_stats.heap_max, max_addr);
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc and friends. If
///    `ptr == NULL`, does nothing. The free was called at location
///    `file`:`line`.

void m61_free(void *ptr, const char *file, int line) {
    // (void) file, (void) line;   // avoid uninitialized variable warnings

    if (!ptr) {
        // Cannot free null pointer
        return;
    }

    // Check if pointer was once allocated OR pointer is in block of allocated
    // Do 2 checks in one loop so cannot use the `metalist_find` function
    meta_t *curr;
    for (curr = meta_list; curr != NULL && curr->payload_addr != ptr; curr = curr->next) {

        // Define min/max range
        void *min_addr = curr->payload_addr;
        void *max_addr = (void *) ((char *) min_addr + curr->payload_sz);
        int malloc_line = curr->line;

        if (ptr > min_addr && ptr < max_addr) {
           printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", file, line, ptr);
           printf("  %s:%d: %p is %ld bytes inside a %zu byte region allocated here\n", file, malloc_line, ptr, ptr - min_addr, curr->payload_sz);
           return;
        }

    }

    if (!curr) {
        printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
        return;
    }

    size_t meta_sz = sizeof(meta_t);
    meta_t *meta_ptr = (meta_t *) ((char *) (ptr - meta_sz));
    size_t payload_sz = meta_ptr->payload_sz;

    // Detect wild write
    int *footer = (int *) ((char *) (ptr + payload_sz));
    
    if (*footer != MAGIC_NUMBER) {
        printf("MEMORY BUG: %s:%d: detected wild write during free of pointer %p\n", file, line, ptr);
        return;
    }

    update_statistics_free(payload_sz);

    metalist_remove(ptr);

    base_free(meta_ptr);
}

void update_statistics_free(size_t payload_sz) {
    global_stats.nactive--;
    global_stats.active_size -= payload_sz;
}


/// m61_realloc(ptr, sz, file, line)
///    Reallocate the dynamic memory pointed to by `ptr` to hold at least
///    `sz` bytes, returning a pointer to the new block. If `ptr` is NULL,
///    behaves like `m61_malloc(sz, file, line)`. If `sz` is 0, behaves
///    like `m61_free(ptr, file, line)`. The allocation request was at
///    location `file`:`line`.

void* m61_realloc(void* ptr, size_t sz, const char* file, int line) {
    void* new_ptr = NULL;
    if (sz) {
        new_ptr = m61_malloc(sz, file, line);
    }
    if (ptr && new_ptr) {
        // Copy the data from `ptr` into `new_ptr`.
        // To do that, we must figure out the size of allocation `ptr`.

        meta_t *node = metalist_find(ptr);
        if (!node) {
            printf("MEMORY BUG: %s:%d: invalid realloc of pointer %p, not in heap\n", file, line, ptr);
            return NULL;
        }

        // meta_t *meta_ptr = (meta_t *) ((char *) ptr - sizeof(meta_t));
        // size_t old_sz = meta_ptr->payload_sz;
        memcpy(new_ptr, ptr, sz);
    }
    m61_free(ptr, file, line);
    return new_ptr;
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    is initialized to zero. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, int line) {
    size_t total_sz = nmemb * sz;

    // Overflow check
    if (nmemb > total_sz || nmemb < 0 || sz < 0 || total_sz < 0 || total_sz > 0xffffffff) {
        global_stats.nfail++;
        return NULL;
    }

    void* ptr = m61_malloc(total_sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


/// m61_getstatistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_getstatistics(struct m61_statistics* stats) {
    *stats = global_stats;
}


/// m61_printstatistics()
///    Print the current memory statistics.

void m61_printstatistics(void) {
    struct m61_statistics stats;
    m61_getstatistics(&stats);

    printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_printleakreport()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_printleakreport(void) {
    for (meta_t *curr = meta_list; curr != NULL; curr = curr->next) {
        printf("LEAK CHECK: %s:%d: allocated object %p with size %zu\n", curr->file, curr->line, curr->payload_addr, curr->payload_sz);
    }
}
