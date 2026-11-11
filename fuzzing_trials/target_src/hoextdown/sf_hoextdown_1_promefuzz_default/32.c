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
    buffer->buffer_free(buffer);
}

int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize renderer
    hoedown_html_flags render_flags = HOEDOWN_HTML_USE_XHTML;
    int nesting_level = 16;
    hoedown_renderer *renderer = hoedown_html_renderer_new(render_flags, nesting_level);
    if (!renderer) return 0;

    // Initialize document
    hoedown_extensions extensions = HOEDOWN_EXT_FOOTNOTES | HOEDOWN_EXT_TABLES;
    hoedown_user_block user_block = {0};
    hoedown_buffer *meta = NULL;
    hoedown_document *doc = hoedown_document_new(renderer, extensions, nesting_level, 0, user_block, meta);
    if (!doc) {
        free(renderer);
        return 0;
    }

    // Initialize buffers
    hoedown_buffer *output_buffer = (hoedown_buffer *)malloc(sizeof(hoedown_buffer));
    initialize_buffer(output_buffer, 64);

    // Fuzz hoedown_document_render_inline
    hoedown_document_render_inline(doc, output_buffer, Data, Size);

    // Fuzz hoedown_document_link_inline_attr
    const hoedown_buffer *link_attr = hoedown_document_link_inline_attr(doc);

    // Fuzz hoedown_document_render
    hoedown_document_render(doc, output_buffer, Data, Size);

    // Cleanup
    free_buffer(output_buffer);
    hoedown_document_free(doc);
    free(renderer);

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

        LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    