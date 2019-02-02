#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

// Utility macros
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static struct m61_statistics global_stats = {
    .nactive = 0,                           // # active allocations
    .active_size = 0,                       // # bytes in active allocations
    .ntotal = 0,                            // # total allocations
    .total_size = 0,                        // # bytes in total allocations
    .nfail = 0,                             // # failed allocation attempts
    .fail_size = 0,                         // # bytes in failed alloc attempts
    .heap_min = (char *) 0xffffffffffff,    // smallest allocated addr
    .heap_max = (char *) 0x000000000000     // largest allocated addr
};

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

    size_t meta_size = sizeof(mem_meta);
    size_t required_size = sz + meta_size;
    void *malloc_ptr = base_malloc(required_size);

    if (!malloc_ptr) {
        // Handle base_malloc failure
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return malloc_ptr;
    }
    
    mem_meta *meta_ptr = (mem_meta *) malloc_ptr;
    void *payload_ptr = (void *) ((char *) (malloc_ptr + meta_size));

    // Initialise meta data
    meta_ptr->payload_sz = sz;
    meta_ptr->payload_addr = payload_ptr;

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
    (void) file, (void) line;   // avoid uninitialized variable warnings

    if (!ptr) {
        // Cannot free null pointer
        return;
    }

    size_t meta_sz = sizeof(mem_meta);
    mem_meta *meta_ptr = (mem_meta *) ((char *) (ptr - meta_sz));

    size_t payload_sz = meta_ptr->payload_sz;
    update_statistics_free(payload_sz);

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
        // Your code here (to fix test014).
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
    // Your code here (to fix test016).
    void* ptr = m61_malloc(nmemb * sz, file, line);
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
    // Your code here.
}
