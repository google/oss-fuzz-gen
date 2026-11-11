#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void test_janet_sfree(void *mem) {
    if (mem) {
        janet_sfree(mem);
    }
}

static void *test_janet_srealloc(void *mem, size_t size) {
    return janet_srealloc(mem, size);
}

static void *test_janet_realloc(void *ptr, size_t size) {
    return janet_realloc(ptr, size);
}

static void test_janet_free(void *ptr) {
    if (ptr) {
        janet_free(ptr);
    }
}

static void test_janet_sfinalizer(void *mem, JanetScratchFinalizer finalizer) {
    if (mem) {
        janet_sfinalizer(mem, finalizer);
    }
}

static void test_janet_deinit() {
    janet_deinit();
}

int LLVMFuzzerTestOneInput_869(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return 0;

    size_t alloc_size = *((size_t *)Data);
    Data += sizeof(size_t);
    Size -= sizeof(size_t);

    // Initialize Janet VM
    janet_init();

    // Ensure that allocation size is reasonable to avoid out of memory issues
    alloc_size = alloc_size % (1024 * 1024); // Limit to 1MB for safer testing

    // Test janet_srealloc
    void *mem = janet_srealloc(NULL, alloc_size);
    if (mem) {
        // Test janet_sfree
        test_janet_sfree(mem);

        // Reallocate with janet_srealloc
        mem = janet_srealloc(NULL, alloc_size);
        if (mem) {
            // Test janet_sfree again
            test_janet_sfree(mem);
        }
    }

    // Test janet_realloc
    void *ptr = janet_realloc(NULL, alloc_size);
    if (ptr) {
        ptr = test_janet_realloc(ptr, alloc_size / 2);
        if (ptr) {
            test_janet_free(ptr);
        }
    }

    // Test janet_sfinalizer and janet_deinit
    mem = janet_srealloc(NULL, alloc_size);
    if (mem) {
        test_janet_sfinalizer(mem, NULL);
        test_janet_sfree(mem);
    }

    test_janet_deinit();

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_869(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
