// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
// hoedown_buffer_printf at buffer.c:238:1 in buffer.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "document.h"
#include "buffer.h"

static void test_hoedown_document_render_inline(hoedown_document *doc, hoedown_buffer *ob, const uint8_t *data, size_t size) {
    if (doc && ob && data) {
        hoedown_document_render_inline(doc, ob, data, size);
    }
}

static void test_hoedown_buffer_put(hoedown_buffer *buf, const uint8_t *data, size_t size) {
    if (buf && data) {
        hoedown_buffer_put(buf, data, size);
    }
}

static void test_hoedown_buffer_printf(hoedown_buffer *buf, const char *fmt, int value) {
    if (buf && fmt) {
        hoedown_buffer_printf(buf, fmt, value);
    }
}

static hoedown_document* create_hoedown_document() {
    hoedown_renderer renderer = {0}; // Use default or mock renderer
    hoedown_extensions extensions = HOEDOWN_EXT_TABLES | HOEDOWN_EXT_FOOTNOTES;
    size_t max_nesting = 16;
    uint8_t attr_activation = 0;
    hoedown_user_block user_block = NULL;
    hoedown_buffer *meta = NULL;

    return hoedown_document_new(&renderer, extensions, max_nesting, attr_activation, user_block, meta);
}

static hoedown_buffer* create_hoedown_buffer(size_t unit) {
    return hoedown_buffer_new(unit);
}

int LLVMFuzzerTestOneInput_70(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data

    hoedown_buffer *buffer = create_hoedown_buffer(64);
    hoedown_document *document = create_hoedown_document();

    if (!buffer || !document) {
        if (buffer) buffer->buffer_free(buffer);
        if (document) free(document);
        return 0;
    }

    // Test hoedown_buffer_put
    test_hoedown_buffer_put(buffer, Data, Size);

    // Test hoedown_buffer_printf with a simple format string
    test_hoedown_buffer_printf(buffer, "Formatted output: %d", Data[0]);

    // Test hoedown_document_render_inline
    test_hoedown_document_render_inline(document, buffer, Data, Size);

    // Clean up
    buffer->buffer_free(buffer);
    free(document);

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

        LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    