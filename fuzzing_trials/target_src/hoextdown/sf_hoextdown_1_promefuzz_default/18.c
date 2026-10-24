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
#include <stdlib.h>
#include <string.h>
#include "html.h"
#include "document.h"

static hoedown_buffer *create_buffer(size_t size) {
    hoedown_buffer *buffer = (hoedown_buffer *)malloc(sizeof(hoedown_buffer));
    if (!buffer) return NULL;

    buffer->data = (uint8_t *)malloc(size);
    if (!buffer->data) {
        free(buffer);
        return NULL;
    }

    buffer->size = 0;
    buffer->asize = size;
    buffer->unit = 64; // Set a default unit size for realloc
    buffer->data_realloc = NULL;
    buffer->data_free = free;
    buffer->buffer_free = free;

    return buffer;
}

static void free_buffer(hoedown_buffer *buffer) {
    if (buffer) {
        if (buffer->data) free(buffer->data);
        free(buffer);
    }
}

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);
    if (!renderer) return 0;

    // Create a document
    hoedown_document *document = hoedown_document_new(renderer, 0, 16, 0, NULL, NULL);
    if (!document) {
        free(renderer);
        return 0;
    }

    // Create output buffer
    hoedown_buffer *output_buffer = create_buffer(256);
    if (!output_buffer) {
        hoedown_document_free(document);
        free(renderer);
        return 0;
    }

    // Render inline markdown
    if (Size > 0) {
        hoedown_document_render_inline(document, output_buffer, Data, Size);
    }

    // Retrieve link inline attributes
    const hoedown_buffer *link_attrs = hoedown_document_link_inline_attr(document);

    // Render full markdown
    if (Size > 0) {
        hoedown_document_render(document, output_buffer, Data, Size);
    }

    // Cleanup
    hoedown_document_free(document);
    free(renderer);
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    