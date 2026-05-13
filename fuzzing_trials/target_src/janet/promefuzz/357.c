// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_scalloc at gc.c:725:7 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_scalloc at gc.c:725:7 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void fuzz_janet_calloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t nmemb;
    size_t elem_size;
    memcpy(&nmemb, Data, sizeof(size_t));
    memcpy(&elem_size, Data + sizeof(size_t), sizeof(size_t));

    void *ptr = janet_calloc(nmemb, elem_size);
    if (ptr) {
        free(ptr);
    }
}

static void fuzz_janet_srealloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t initial_size;
    size_t new_size;
    memcpy(&initial_size, Data, sizeof(size_t));
    memcpy(&new_size, Data + sizeof(size_t), sizeof(size_t));

    if (initial_size == 0) return;

    void *ptr = janet_scalloc(1, initial_size);
    if (ptr) {
        void *new_ptr = janet_srealloc(ptr, new_size);
        if (new_ptr) {
            janet_srealloc(new_ptr, 0); // Free the memory
        } else {
            janet_srealloc(ptr, 0); // Free the original memory if realloc failed
        }
    }
}

static void fuzz_janet_realloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t initial_size;
    size_t new_size;
    memcpy(&initial_size, Data, sizeof(size_t));
    memcpy(&new_size, Data + sizeof(size_t), sizeof(size_t));

    void *ptr = janet_malloc(initial_size);
    if (ptr) {
        void *new_ptr = janet_realloc(ptr, new_size);
        if (new_ptr) {
            free(new_ptr);
        } else {
            free(ptr);
        }
    }
}

static void fuzz_janet_malloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;

    size_t alloc_size;
    memcpy(&alloc_size, Data, sizeof(size_t));

    void *ptr = janet_malloc(alloc_size);
    if (ptr) {
        free(ptr);
    }
}

static void fuzz_janet_scalloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t) * 2) return;

    size_t nmemb;
    size_t elem_size;
    memcpy(&nmemb, Data, sizeof(size_t));
    memcpy(&elem_size, Data + sizeof(size_t), sizeof(size_t));

    if (nmemb == 0 || elem_size == 0) return;

    void *ptr = janet_scalloc(nmemb, elem_size);
    if (ptr) {
        janet_srealloc(ptr, 0); // Free the memory
    }
}

int LLVMFuzzerTestOneInput_357(const uint8_t *Data, size_t Size) {
    fuzz_janet_calloc(Data, Size);
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

        LLVMFuzzerTestOneInput_357(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    