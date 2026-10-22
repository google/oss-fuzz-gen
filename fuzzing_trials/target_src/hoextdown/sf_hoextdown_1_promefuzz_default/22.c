// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_document_link_inline_attr at document.c:4279:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_html_renderer_free at html.c:1185:1 in html.h
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

static void initialize_buffer(hoedown_buffer *buffer, size_t size) {
    buffer->data = (uint8_t *)malloc(size);
    buffer->size = 0;
    buffer->asize = size;
    buffer->unit = 64;
    buffer->data_realloc = NULL;
    buffer->data_free = free;
    buffer->buffer_free = free;
}

static void free_buffer(hoedown_buffer *buffer) {
    if (buffer->data_free) {
        buffer->data_free(buffer->data);
    }
    if (buffer->buffer_free) {
        buffer->buffer_free(buffer);
    }
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hoedown_html_flags render_flags = HOEDOWN_HTML_USE_XHTML;
    int nesting_level = 16;
    hoedown_renderer *renderer = hoedown_html_renderer_new(render_flags, nesting_level);

    hoedown_extensions extensions = HOEDOWN_EXT_FOOTNOTES;
    size_t max_nesting = 16;
    uint8_t attr_activation = 1;
    hoedown_user_block user_block = NULL;
    hoedown_buffer *meta = NULL;

    hoedown_document *document = hoedown_document_new(renderer, extensions, max_nesting, attr_activation, user_block, meta);

    hoedown_buffer *output_buffer = (hoedown_buffer *)malloc(sizeof(hoedown_buffer));
    initialize_buffer(output_buffer, 1024);

    hoedown_document_render_inline(document, output_buffer, Data, Size);
    hoedown_document_render(document, output_buffer, Data, Size);

    const hoedown_buffer *link_inline_attr = hoedown_document_link_inline_attr(document);

    hoedown_document_free(document);
    hoedown_html_renderer_free(renderer);
    free_buffer(output_buffer);

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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    