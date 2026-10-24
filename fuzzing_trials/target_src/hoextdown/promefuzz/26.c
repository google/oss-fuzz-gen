// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_buffer_putc at buffer.c:138:1 in buffer.h
// hoedown_buffer_printf at buffer.c:238:1 in buffer.h
// hoedown_buffer_grow at buffer.c:103:1 in buffer.h
// hoedown_buffer_reset at buffer.c:93:1 in buffer.h
// hoedown_buffer_uninit at buffer.c:66:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "buffer.h"

// Dummy realloc and free functions
static void *my_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

static void my_free(void *ptr) {
    free(ptr);
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize a new buffer with a non-zero unit size
    size_t unit_size = Data[0] ? Data[0] : 1; // Ensure non-zero
    hoedown_buffer *buffer = hoedown_buffer_new(unit_size);
    if (!buffer) return 0;

    // Set up buffer's reallocation and free callbacks
    buffer->data_realloc = my_realloc;
    buffer->data_free = my_free;

    // Test hoedown_buffer_putc with the remaining data
    for (size_t i = 1; i < Size; ++i) {
        hoedown_buffer_putc(buffer, Data[i]);
    }

    // Test hoedown_buffer_printf with a simple format
    hoedown_buffer_printf(buffer, "Test %d", 123);

    // Test hoedown_buffer_grow
    hoedown_buffer_grow(buffer, buffer->asize + 10);

    // Test hoedown_buffer_reset
    hoedown_buffer_reset(buffer);

    // Test hoedown_buffer_uninit
    hoedown_buffer_uninit(buffer);

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    