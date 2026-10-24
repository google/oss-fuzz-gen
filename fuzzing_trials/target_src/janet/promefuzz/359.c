// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_smalloc at gc.c:706:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_smalloc at gc.c:706:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
// janet_scalloc at gc.c:725:7 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h"

#define MAX_ALLOC_SIZE 1024 * 1024 * 10 // 10 MB

static void fuzz_janet_smalloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t alloc_size = *((size_t *)Data) % MAX_ALLOC_SIZE;
    void *ptr = janet_smalloc(alloc_size);
    if (ptr) {
        janet_gcpressure(alloc_size);
        // Normally, you would use the allocated memory here
        // For fuzzing, just free it using the appropriate Janet function
        janet_srealloc(ptr, 0);
    }
}

static void fuzz_janet_calloc(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(size_t)) return;
    size_t nmemb = ((size_t *)Data)[0] % MAX_ALLOC_SIZE;
    size_t elem_size = ((size_t *)Data)[1] % MAX_ALLOC_SIZE;
    if (nmemb > 0 && elem_size > 0 && nmemb <= SIZE_MAX / elem_size) {
        void *ptr = janet_calloc(nmemb, elem_size);
        if (ptr) {
            janet_gcpressure(nmemb * elem_size);
            // Normally, you would use the allocated memory here
            // For fuzzing, just free it using the appropriate Janet function
            janet_srealloc(ptr, 0);
        }
    }
}

static void fuzz_janet_srealloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t alloc_size = *((size_t *)Data) % MAX_ALLOC_SIZE;
    void *ptr = janet_smalloc(alloc_size);
    if (ptr) {
        janet_gcpressure(alloc_size);
        size_t new_size = alloc_size / 2;
        void *new_ptr = janet_srealloc(ptr, new_size);
        if (new_ptr) {
            janet_gcpressure(new_size);
            janet_srealloc(new_ptr, 0);
        }
    }
}

static void fuzz_janet_realloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t alloc_size = *((size_t *)Data) % MAX_ALLOC_SIZE;
    void *ptr = malloc(alloc_size);
    if (ptr) {
        void *new_ptr = janet_realloc(ptr, alloc_size / 2);
        if (new_ptr) {
            free(new_ptr);
        }
    }
}

static void fuzz_janet_scalloc(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(size_t)) return;
    size_t nmemb = ((size_t *)Data)[0] % MAX_ALLOC_SIZE;
    size_t elem_size = ((size_t *)Data)[1] % MAX_ALLOC_SIZE;
    if (nmemb > 0 && elem_size > 0 && nmemb <= SIZE_MAX / elem_size) {
        void *ptr = janet_scalloc(nmemb, elem_size);
        if (ptr) {
            janet_gcpressure(nmemb * elem_size);
            janet_srealloc(ptr, 0);
        }
    }
}

int LLVMFuzzerTestOneInput_359(const uint8_t *Data, size_t Size) {
    fuzz_janet_smalloc(Data, Size);
    fuzz_janet_calloc(Data, Size);
    fuzz_janet_srealloc(Data, Size);
    fuzz_janet_realloc(Data, Size);
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

        LLVMFuzzerTestOneInput_359(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    