// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
// hoedown_buffer_cstr at buffer.c:224:1 in buffer.h
// hoedown_buffer_eqs at buffer.c:188:1 in buffer.h
// hoedown_buffer_sets at buffer.c:175:1 in buffer.h
// hoedown_buffer_puts at buffer.c:132:1 in buffer.h
// hoedown_buffer_printf at buffer.c:238:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "buffer.h"

static hoedown_buffer *initialize_buffer(size_t size) {
    hoedown_buffer *buf = (hoedown_buffer *)malloc(sizeof(hoedown_buffer));
    if (!buf) return NULL;

    buf->data = (uint8_t *)malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    buf->size = 0;
    buf->asize = size;
    buf->unit = 64; // Default unit size for reallocations
    buf->data_realloc = realloc;
    buf->data_free = free;
    buf->buffer_free = free;

    return buf;
}

static void cleanup_buffer(hoedown_buffer *buf) {
    if (buf) {
        if (buf->data) buf->data_free(buf->data);
        buf->buffer_free(buf);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    hoedown_buffer *buf = initialize_buffer(128);
    if (!buf) return 0;

    // Fuzz hoedown_buffer_put
    hoedown_buffer_put(buf, Data, Size);

    // Fuzz hoedown_buffer_cstr
    const char *cstr = hoedown_buffer_cstr(buf);

    // Fuzz hoedown_buffer_eqs
    if (Size > 0) {
        // Ensure the data is null-terminated before passing to hoedown_buffer_eqs
        char *data_copy = (char *)malloc(Size + 1);
        if (data_copy) {
            memcpy(data_copy, Data, Size);
            data_copy[Size] = '\0';
            hoedown_buffer_eqs(buf, data_copy);
            free(data_copy);
        }
    }

    // Fuzz hoedown_buffer_sets
    hoedown_buffer_sets(buf, "example string");

    // Fuzz hoedown_buffer_puts
    hoedown_buffer_puts(buf, "additional string");

    // Fuzz hoedown_buffer_printf
    hoedown_buffer_printf(buf, "Formatted output: %d", Size);

    cleanup_buffer(buf);
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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    