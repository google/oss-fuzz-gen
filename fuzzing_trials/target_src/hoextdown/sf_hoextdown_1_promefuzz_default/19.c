// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_document_link_inline_attr at document.c:4279:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
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

static hoedown_buffer *create_buffer(size_t unit) {
    hoedown_buffer *buffer = (hoedown_buffer *)malloc(sizeof(hoedown_buffer));
    if (!buffer) return NULL;
    buffer->data = NULL;
    buffer->size = 0;
    buffer->asize = 0;
    buffer->unit = unit;
    buffer->data_realloc = realloc; // Initialize data_realloc with realloc
    return buffer;
}

static void free_buffer(hoedown_buffer *buffer) {
    if (!buffer) return;
    if (buffer->data) free(buffer->data);
    free(buffer);
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(HOEDOWN_HTML_USE_XHTML, 0);
    if (!renderer) return 0;

    // Create a document
    hoedown_document *doc = hoedown_document_new(renderer, HOEDOWN_EXT_FOOTNOTES, 16, 0, NULL, NULL);
    if (!doc) {
        free(renderer);
        return 0;
    }

    // Create output buffer
    hoedown_buffer *ob = create_buffer(64);
    if (!ob) {
        hoedown_document_free(doc);
        free(renderer);
        return 0;
    }

    // Fuzz hoedown_document_render_inline
    hoedown_document_render_inline(doc, ob, Data, Size);

    // Fuzz hoedown_document_render
    hoedown_document_render(doc, ob, Data, Size);

    // Fuzz hoedown_document_link_inline_attr
    const hoedown_buffer *attr = hoedown_document_link_inline_attr(doc);

    // Cleanup
    free_buffer(ob);
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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    