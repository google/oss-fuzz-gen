// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_smalloc at gc.c:706:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_smalloc at gc.c:706:7 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_smalloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t alloc_size = *(size_t *)Data;
    // Ensure the allocation size is within a reasonable range
    if (alloc_size > (1 << 20)) return; // Limit to 1 MB for example
    void *ptr = janet_smalloc(alloc_size);
    if (ptr) {
        janet_gcpressure(alloc_size);
        // Normally, the allocated memory would be used here
        // Cleanup would be handled by Janet's garbage collector
    }
}

static void fuzz_janet_calloc(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(size_t)) return;
    size_t nmemb = *(size_t *)Data;
    size_t elem_size = *(size_t *)(Data + sizeof(size_t));
    // Ensure the total allocation size is within a reasonable range
    if (nmemb > (1 << 20) || elem_size > (1 << 20)) return; // Limit elements and size
    void *ptr = janet_calloc(nmemb, elem_size);
    if (ptr) {
        janet_gcpressure(nmemb * elem_size);
        // Normally, the allocated memory would be used here
        // Cleanup would be handled by Janet's garbage collector
    }
}

static void fuzz_janet_srealloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t new_size = *(size_t *)Data;
    // Ensure the new size is within a reasonable range
    if (new_size > (1 << 20)) return; // Limit to 1 MB for example
    void *ptr = janet_smalloc(128); // Initial allocation
    if (ptr) {
        void *new_ptr = janet_srealloc(ptr, new_size);
        if (new_ptr) {
            janet_gcpressure(new_size);
            // Normally, the reallocated memory would be used here
        }
    }
}

static void fuzz_janet_realloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t new_size = *(size_t *)Data;
    // Ensure the new size is within a reasonable range
    if (new_size > (1 << 20)) return; // Limit to 1 MB for example
    void *ptr = malloc(128); // Initial allocation with standard malloc
    if (ptr) {
        void *new_ptr = janet_realloc(ptr, new_size);
        if (new_ptr) {
            // Normally, the reallocated memory would be used here
        }
        // Free memory since Janet's GC won't manage this
        free(new_ptr);
    }
}

int LLVMFuzzerTestOneInput_221(const uint8_t *Data, size_t Size) {
    fuzz_janet_smalloc(Data, Size);
    fuzz_janet_calloc(Data, Size);
    fuzz_janet_srealloc(Data, Size);
    fuzz_janet_realloc(Data, Size);
    return 0;
}
    #ifdef INC_MAIN
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    int main(int argc, char *argv[])
    {
        FILE *f;
        uint8_t *data = NULL;
        long size;

        if(argc < 2)
            exit(0);

        f = fopen(argv[1], "rb");
        if(f == NULL)
            exit(0);

        fseek(f, 0, SEEK_END);

        size = ftell(f);
        rewind(f);

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_221(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    