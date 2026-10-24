// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_link_inline_attr at document.c:4279:1 in document.h
// hoedown_document_footnote_id at document.c:4303:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "html.h"
#include "document.h"

static hoedown_renderer *create_renderer() {
    // Create a renderer with random flags and nesting levels
    hoedown_html_flags flags = HOEDOWN_HTML_SKIP_HTML | HOEDOWN_HTML_ESCAPE;
    int nesting_level = 3;
    return hoedown_html_renderer_new(flags, nesting_level);
}

static hoedown_document *create_document(const uint8_t *data, size_t size) {
    hoedown_renderer *renderer = create_renderer();
    if (!renderer) return NULL;

    hoedown_extensions extensions = HOEDOWN_EXT_TABLES | HOEDOWN_EXT_FOOTNOTES;
    size_t max_nesting = 16;
    uint8_t attr_activation = 1;
    hoedown_user_block user_block = {0};
    hoedown_buffer *meta = NULL;

    hoedown_document *document = hoedown_document_new(renderer, extensions, max_nesting, attr_activation, user_block, meta);
    return document;
}

static void test_document_functions(hoedown_document *document, const uint8_t *data, size_t size) {
    if (!document) return;

    // Test hoedown_document_link_inline_attr
    const hoedown_buffer *link_inline_attr = hoedown_document_link_inline_attr(document);

    // Test hoedown_document_footnote_id
    const hoedown_buffer *footnote_id = hoedown_document_footnote_id(document);

    // Test hoedown_document_render
    hoedown_buffer *output_buffer = malloc(sizeof(hoedown_buffer));
    if (output_buffer) {
        output_buffer->data = malloc(size > 0 ? size : 1); // Ensure non-zero allocation
        output_buffer->size = 0;
        output_buffer->asize = size;
        output_buffer->unit = 64;
        output_buffer->data_realloc = realloc;
        output_buffer->data_free = free;
        output_buffer->buffer_free = free;
        hoedown_document_render(document, output_buffer, data, size);
        free(output_buffer->data);
        free(output_buffer);
    }
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    hoedown_document *document = create_document(Data, Size);
    if (document) {
        test_document_functions(document, Data, Size);
        hoedown_document_free(document);
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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    