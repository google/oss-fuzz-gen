// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_smalloc at gc.c:706:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_smalloc at gc.c:706:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "janet.h"

static void test_janet_smalloc(size_t size) {
    void *mem = janet_smalloc(size);
    if (mem) {
        janet_gcpressure(size);
    }
    // Note: Memory cleanup would be handled by Janet's GC, not manually
}

static void test_janet_calloc(size_t nmemb, size_t size) {
    void *mem = janet_calloc(nmemb, size);
    if (mem) {
        janet_gcpressure(nmemb * size);
    }
    // Note: Memory cleanup would be handled by Janet's GC, not manually
}

static void test_janet_srealloc(void *mem, size_t size) {
    void *new_mem = janet_srealloc(mem, size);
    if (new_mem) {
        janet_gcpressure(size);
    }
    // Note: Memory cleanup would be handled by Janet's GC, not manually
}

static void test_janet_realloc(void *mem, size_t size) {
    // janet_realloc should only be used with memory initially allocated by janet_malloc
    void *new_mem = janet_realloc(NULL, size); // Allocate new memory
    if (new_mem) {
        // Memory management would be handled by Janet's GC
    }
    // Note: Memory cleanup would be handled by Janet's GC, not manually
}

int LLVMFuzzerTestOneInput_376(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    size_t sm_size = Data[0] % 256;
    size_t ca_nmemb = Data[0] % 16;
    size_t ca_size = Data[0] % 16;
    size_t sr_size = Data[0] % 256;
    size_t r_size = Data[0] % 256;

    // Test janet_smalloc
    test_janet_smalloc(sm_size);

    // Test janet_calloc
    test_janet_calloc(ca_nmemb, ca_size);

    // Allocate initial memory for janet_srealloc test
    void *sr_mem = janet_smalloc(8);
    if (sr_mem) {
        test_janet_srealloc(sr_mem, sr_size);
    }

    // Test janet_realloc with a fresh allocation
    test_janet_realloc(NULL, r_size);

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

        LLVMFuzzerTestOneInput_376(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    