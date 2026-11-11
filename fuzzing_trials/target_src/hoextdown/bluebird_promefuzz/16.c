#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/hoextdown/src/buffer.h"
#include "/src/hoextdown/src/escape.h"

static void initialize_buffer(hoedown_buffer *buf, size_t unit) {
    buf->data = NULL;
    buf->size = 0;
    buf->asize = 0;
    buf->unit = unit;
    buf->data_realloc = realloc;
    buf->data_free = free;
    buf->buffer_free = free;
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz hoedown_buffer_new
    size_t unit_size = Data[0] ? Data[0] : 1;
    hoedown_buffer *buffer = hoedown_buffer_new(unit_size);
    if (!buffer) return 0;

    // Fuzz hoedown_buffer_eq
    hoedown_buffer_eq(buffer, Data, Size);

    // Fuzz hoedown_escape_html
    hoedown_escape_html(buffer, Data, Size, 1);

    // Fuzz hoedown_buffer_prefix
    char *prefix = (char *)malloc(Size + 1);
    if (prefix) {
        memcpy(prefix, Data, Size);
        prefix[Size] = '\0';
        hoedown_buffer_prefix(buffer, prefix);
        free(prefix);
    }

    // Fuzz hoedown_buffer_put_utf8
    unsigned int codepoint = Data[0];
    hoedown_buffer_put_utf8(buffer, codepoint);

    // Fuzz hoedown_buffer_grow
    size_t new_size = Size + (Size / 2);
    hoedown_buffer_grow(buffer, new_size);

    // Cleanup
    buffer->buffer_free(buffer);

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
