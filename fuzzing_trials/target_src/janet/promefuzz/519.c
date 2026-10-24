// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_smalloc at gc.c:706:7 in janet.h
// janet_smalloc at gc.c:706:7 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_scalloc at gc.c:725:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "janet.h"

#define MAX_ALLOCATION_SIZE 1024

static void fuzz_janet_smalloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t alloc_size = *((size_t *)Data) % MAX_ALLOCATION_SIZE;
    void *ptr = janet_smalloc(alloc_size);
    if (ptr) {
        // Simulate usage of allocated memory
        // Memory allocated by janet_smalloc should not be freed with janet_free
        // janet_smalloc is for scratch memory and managed by Janet's GC
    }
}

static void fuzz_janet_srealloc(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(size_t)) return;
    size_t initial_size = *((size_t *)Data) % MAX_ALLOCATION_SIZE;
    size_t new_size = *((size_t *)(Data + sizeof(size_t))) % MAX_ALLOCATION_SIZE;
    void *ptr = janet_smalloc(initial_size);
    if (ptr) {
        ptr = janet_srealloc(ptr, new_size);
        if (ptr) {
            // Simulate usage of reallocated memory
            // Memory should not be freed with janet_free
        }
    }
}

static void fuzz_janet_realloc(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(size_t)) return;
    size_t initial_size = *((size_t *)Data) % MAX_ALLOCATION_SIZE;
    size_t new_size = *((size_t *)(Data + sizeof(size_t))) % MAX_ALLOCATION_SIZE;
    void *ptr = janet_malloc(initial_size);
    if (ptr) {
        ptr = janet_realloc(ptr, new_size);
        if (ptr) {
            // Simulate usage of reallocated memory
            janet_free(ptr);
        }
    }
}

static void fuzz_janet_malloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t alloc_size = *((size_t *)Data) % MAX_ALLOCATION_SIZE;
    void *ptr = janet_malloc(alloc_size);
    if (ptr) {
        // Simulate usage of allocated memory
        janet_free(ptr);
    }
}

static void fuzz_janet_scalloc(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(size_t)) return;
    size_t nmemb = *((size_t *)Data) % MAX_ALLOCATION_SIZE;
    size_t size = *((size_t *)(Data + sizeof(size_t))) % MAX_ALLOCATION_SIZE;
    void *ptr = janet_scalloc(nmemb, size);
    if (ptr) {
        // Simulate usage of allocated memory
        // Memory should not be freed with janet_free
    }
}

int LLVMFuzzerTestOneInput_519(const uint8_t *Data, size_t Size) {
    fuzz_janet_smalloc(Data, Size);
    fuzz_janet_srealloc(Data, Size);
    fuzz_janet_realloc(Data, Size);
    fuzz_janet_malloc(Data, Size);
    fuzz_janet_scalloc(Data, Size);
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

        LLVMFuzzerTestOneInput_519(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    