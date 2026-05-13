#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h"
#include "/src/hoextdown/src/escape.h"

static void initialize_buffer(hoedown_buffer *buf) {
    buf->data = NULL;
    buf->size = 0;
    buf->asize = 0;
    buf->unit = 64; // Arbitrary unit size for reallocation
    buf->data_realloc = realloc;
    buf->data_free = free;
    buf->buffer_free = free;
}

static void cleanup_buffer(hoedown_buffer *buf) {
    if (buf->data) {
        buf->data_free(buf->data);
    }
    buf->data = NULL;
    buf->size = 0;
    buf->asize = 0;
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    hoedown_buffer buf;
    initialize_buffer(&buf);

    // Fuzz hoedown_buffer_set
    hoedown_buffer_set(&buf, Data, Size);

    // Fuzz hoedown_buffer_slurp
    if (Size > 0) {
        size_t slurp_size = Data[0] % (Size + 1); // Ensure slurp_size <= Size
        hoedown_buffer_slurp(&buf, slurp_size);
    }

    // Fuzz hoedown_buffer_sets
    if (Size > 0) {
        char *str = (char *)malloc(Size + 1);
        if (str) {
            memcpy(str, Data, Size);
            str[Size] = '\0';
            hoedown_buffer_sets(&buf, str);
            free(str);
        }
    }

    // Fuzz hoedown_escape_href
    hoedown_buffer ob;
    initialize_buffer(&ob);
    hoedown_escape_href(&ob, Data, Size);
    cleanup_buffer(&ob);

    // Fuzz hoedown_buffer_puts
    if (Size > 0) {
        char *str = (char *)malloc(Size + 1);
        if (str) {
            memcpy(str, Data, Size);
            str[Size] = '\0';
            // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function hoedown_buffer_puts with hoedown_buffer_printf
            hoedown_buffer_printf(&buf, str);
            // End mutation: Producer.REPLACE_FUNC_MUTATOR
            free(str);
        }
    }

    // Fuzz hoedown_buffer_put
    hoedown_buffer_put(&buf, Data, Size);

    cleanup_buffer(&buf);
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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
