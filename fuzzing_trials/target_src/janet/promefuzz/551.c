// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_smalloc at gc.c:706:7 in janet.h
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
#include "janet.h"

int LLVMFuzzerTestOneInput_551(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz janet_smalloc
    size_t alloc_size = Data[0];
    void *smalloc_ptr = janet_smalloc(alloc_size);
    if (smalloc_ptr) {
        // Fuzz janet_srealloc with janet_smalloc
        size_t new_size = Size > 1 ? Data[1] : alloc_size;
        void *srealloc_ptr = janet_srealloc(smalloc_ptr, new_size);
        if (srealloc_ptr) {
            // Use memory
        }
        // Assume janet_srealloc handles its own memory cleanup
    }

    // Fuzz janet_calloc
    size_t nmemb = Size > 2 ? Data[2] : 1;
    size_t elem_size = Size > 3 ? Data[3] : 1;
    void *calloc_ptr = janet_calloc(nmemb, elem_size);
    if (calloc_ptr) {
        // Fuzz janet_realloc with janet_calloc
        size_t realloc_size = Size > 4 ? Data[4] : nmemb * elem_size;
        void *realloc_ptr = janet_realloc(calloc_ptr, realloc_size);
        if (realloc_ptr) {
            // Use memory
        }
        // Assume janet_realloc handles its own memory cleanup
    }

    // Fuzz janet_scalloc
    void *scalloc_ptr = janet_scalloc(nmemb, elem_size);
    if (scalloc_ptr) {
        // Fuzz janet_srealloc with janet_scalloc
        size_t scalloc_realloc_size = Size > 5 ? Data[5] : nmemb * elem_size;
        void *srealloc_ptr3 = janet_srealloc(scalloc_ptr, scalloc_realloc_size);
        if (srealloc_ptr3) {
            // Use memory
        }
        // Assume janet_srealloc handles its own memory cleanup
    }

    // Fuzz janet_realloc (not using janet_smalloc memory)
    void *realloc_ptr2 = janet_realloc(NULL, alloc_size);
    if (realloc_ptr2) {
        size_t realloc_new_size = Size > 6 ? Data[6] : alloc_size;
        void *realloc_ptr3 = janet_realloc(realloc_ptr2, realloc_new_size);
        if (realloc_ptr3) {
            // Use memory
        }
        // Assume janet_realloc handles its own memory cleanup
    }

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

        LLVMFuzzerTestOneInput_551(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    