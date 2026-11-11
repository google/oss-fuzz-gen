// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_smalloc at gc.c:706:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_83(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return 0;

    // Extract a size value from the input data
    size_t alloc_size = *(const size_t *)Data;
    Data += sizeof(size_t);
    Size -= sizeof(size_t);

    // Limit the allocation size to prevent excessive memory usage
    alloc_size = alloc_size % (1024 * 1024); // Limit to 1MB

    // Test janet_smalloc
    void *ptr = janet_smalloc(alloc_size);
    if (!ptr) return 0;

    // Test janet_gcpressure
    janet_gcpressure(alloc_size);

    // Test janet_srealloc
    if (Size >= sizeof(size_t)) {
        size_t realloc_size = *(const size_t *)Data;
        realloc_size = realloc_size % (1024 * 1024); // Limit to 1MB
        void *new_ptr = janet_srealloc(ptr, realloc_size);
        if (new_ptr) {
            ptr = new_ptr;
            janet_gcpressure(realloc_size);
        }
    }

    // Since ptr was allocated with janet_smalloc, we should not use janet_realloc or janet_free.
    // Proper cleanup for scratch memory is managed by Janet's garbage collector.

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

        LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    