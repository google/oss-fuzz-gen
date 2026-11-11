// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
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

static void dummy_blockcode(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *lang, const hoedown_buffer *attr, const hoedown_renderer_data *data) {}
static void dummy_blockquote(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) {}

static hoedown_renderer *create_dummy_renderer() {
    hoedown_renderer *renderer = malloc(sizeof(hoedown_renderer));
    if (!renderer) return NULL;
    memset(renderer, 0, sizeof(hoedown_renderer));
    renderer->blockcode = dummy_blockcode;
    renderer->blockquote = dummy_blockquote;
    return renderer;
}

static hoedown_buffer *create_buffer(size_t size) {
    hoedown_buffer *buffer = malloc(sizeof(hoedown_buffer));
    if (!buffer) return NULL;
    buffer->data = malloc(size);
    if (!buffer->data) {
        free(buffer);
        return NULL;
    }
    buffer->size = 0;
    buffer->asize = size;
    buffer->unit = 1;
    buffer->data_realloc = realloc;
    buffer->data_free = free;
    buffer->buffer_free = free;
    return buffer;
}

static void free_buffer(hoedown_buffer *buffer) {
    if (buffer) {
        if (buffer->data) buffer->data_free(buffer->data);
        buffer->buffer_free(buffer);
    }
}

int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    // Create a renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);
    if (!renderer) return 0;

    // Create a document
    hoedown_document *doc = hoedown_document_new(renderer, 0, 10, 0, NULL, NULL);
    if (!doc) {
        free(renderer);
        return 0;
    }

    // Create input and output buffers
    hoedown_buffer *ib = create_buffer(Size);
    hoedown_buffer *ob = create_buffer(1024);
    if (!ib || !ob) {
        free_buffer(ib);
        free_buffer(ob);
        hoedown_document_free(doc);
        free(renderer);
        return 0;
    }

    // Copy input data to the input buffer
    memcpy(ib->data, Data, Size);
    ib->size = Size;

    // Test hoedown_document_render_inline
    hoedown_document_render_inline(doc, ob, ib->data, ib->size);

    // Test hoedown_document_link_inline_attr
    const hoedown_buffer *link_attr = hoedown_document_link_inline_attr(doc);

    // Test hoedown_document_render
    hoedown_document_render(doc, ob, ib->data, ib->size);

    // Clean up
    free_buffer(ib);
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

        LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    