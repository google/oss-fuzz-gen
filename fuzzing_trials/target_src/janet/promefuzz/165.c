// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_smalloc at gc.c:706:7 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_sfinalizer at gc.c:754:6 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void dummy_finalizer(void *mem) {
    // A simple finalizer function that does nothing.
}

int LLVMFuzzerTestOneInput_165(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return 0;

    // Extract a size for allocation
    size_t alloc_size = *((size_t *)Data);
    Data += sizeof(size_t);
    Size -= sizeof(size_t);

    // Ensure alloc_size is within a reasonable range to prevent out-of-memory
    if (alloc_size > 1024 * 1024 * 10) { // Limit to 10 MB for safety
        return 0;
    }

    // Fuzz janet_smalloc
    void *mem = janet_smalloc(alloc_size);
    if (!mem) return 0;

    // Fuzz janet_srealloc
    if (Size >= sizeof(size_t)) {
        size_t realloc_size = *((size_t *)Data);
        Data += sizeof(size_t);
        Size -= sizeof(size_t);

        if (realloc_size <= 1024 * 1024 * 10) { // Limit to 10 MB for safety
            mem = janet_srealloc(mem, realloc_size);
            if (!mem) return 0;
        }
    }

    // Fuzz janet_gcpressure
    if (Size >= sizeof(size_t)) {
        size_t gc_size = *((size_t *)Data);
        janet_gcpressure(gc_size);
    }

    // Fuzz janet_sfinalizer
    janet_sfinalizer(mem, dummy_finalizer);

    // Normally, memory would be cleaned up by Janet's GC, but for safety:
    janet_srealloc(mem, 0);

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

        LLVMFuzzerTestOneInput_165(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    