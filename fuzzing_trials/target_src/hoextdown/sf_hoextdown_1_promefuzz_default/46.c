// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_link_inline_attr at document.c:4279:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "html.h"
#include "document.h"

static void initialize_buffer(hoedown_buffer *buffer, size_t unit) {
    buffer->data = (uint8_t *)malloc(unit);
    buffer->size = 0;
    buffer->asize = unit;
    buffer->unit = unit;
    buffer->data_realloc = realloc;
    buffer->data_free = free;
    buffer->buffer_free = free;
}

static void free_buffer(hoedown_buffer *buffer) {
    if (buffer->data) {
        buffer->data_free(buffer->data);
    }
}

int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize a renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(HOEDOWN_HTML_USE_XHTML, 16);
    if (!renderer) return 0;

    // Initialize a document
    hoedown_document *doc = hoedown_document_new(renderer, HOEDOWN_EXT_TABLES, 16, 1, NULL, NULL);
    if (!doc) {
        free(renderer);
        return 0;
    }

    // Initialize input and output buffers
    hoedown_buffer input_buffer;
    initialize_buffer(&input_buffer, 64);
    if (Size < input_buffer.asize) {
        memcpy(input_buffer.data, Data, Size);
        input_buffer.size = Size;
    }

    hoedown_buffer output_buffer;
    initialize_buffer(&output_buffer, 64);

    // Test hoedown_document_render_inline
    hoedown_document_render_inline(doc, &output_buffer, input_buffer.data, input_buffer.size);

    // Test hoedown_document_link_inline_attr
    const hoedown_buffer *link_attr = hoedown_document_link_inline_attr(doc);

    // Test hoedown_document_render
    hoedown_document_render(doc, &output_buffer, input_buffer.data, input_buffer.size);

    // Cleanup
    hoedown_document_free(doc);
    free(renderer);
    free_buffer(&input_buffer);
    free_buffer(&output_buffer);

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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    