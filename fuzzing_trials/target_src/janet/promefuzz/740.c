// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_smalloc at gc.c:706:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_abstract_begin at janet.c:1330:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static const JanetAbstractType myAbstractType = {0}; // Dummy abstract type for testing

int LLVMFuzzerTestOneInput_740(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data to work with

    // Initialize Janet VM
    janet_init();

    // Test janet_smalloc
    size_t malloc_size = Data[0] % 256; // Limit size to 256 for safety
    void *smem = janet_smalloc(malloc_size);
    if (smem) {
        janet_gcpressure(malloc_size);
    }

    // Test janet_abstract_begin
    if (Size > 1) {
        size_t abstract_size = Data[1] % 256; // Limit size to 256 for safety
        void *abstract_mem = janet_abstract_begin(&myAbstractType, abstract_size);
        if (abstract_mem) {
            janet_gcpressure(abstract_size);
        }
    }

    // Test janet_srealloc
    if (smem && Size > 2) {
        size_t realloc_size = Data[2] % 256; // Limit size to 256 for safety
        void *realloc_mem = janet_srealloc(smem, realloc_size);
        if (realloc_mem) {
            janet_gcpressure(realloc_size);
        }
    }

    // Test janet_malloc
    if (Size > 3) {
        size_t malloc_size2 = Data[3] % 256; // Limit size to 256 for safety
        void *mmem = janet_malloc(malloc_size2);
        if (mmem) {
            janet_gcpressure(malloc_size2);
        }
    }

    // Deinitialize Janet VM
    janet_deinit();

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

        LLVMFuzzerTestOneInput_740(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    