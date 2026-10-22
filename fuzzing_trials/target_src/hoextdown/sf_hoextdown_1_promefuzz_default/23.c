// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_link_inline_attr at document.c:4279:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
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

static void fuzz_hoedown_document_render_inline(hoedown_document *doc, const uint8_t *data, size_t size) {
    hoedown_buffer ob;
    ob.data = malloc(size);
    if (!ob.data) return;
    ob.size = 0;
    ob.asize = size;
    ob.unit = 64; // Set a non-zero unit size for buffer growth
    ob.data_realloc = realloc;
    ob.data_free = free;
    ob.buffer_free = NULL;

    hoedown_document_render_inline(doc, &ob, data, size);

    free(ob.data);
}

static void fuzz_hoedown_document_link_inline_attr(hoedown_document *doc) {
    const hoedown_buffer *attr = hoedown_document_link_inline_attr(doc);
    if (attr && attr->data) {
        // Do something with attr->data if needed
    }
}

static void fuzz_hoedown_document_render(hoedown_document *doc, const uint8_t *data, size_t size) {
    hoedown_buffer ob;
    ob.data = malloc(size);
    if (!ob.data) return;
    ob.size = 0;
    ob.asize = size;
    ob.unit = 64; // Set a non-zero unit size for buffer growth
    ob.data_realloc = realloc;
    ob.data_free = free;
    ob.buffer_free = NULL;

    hoedown_document_render(doc, &ob, data, size);

    free(ob.data);
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(HOEDOWN_HTML_USE_XHTML, 0);
    if (!renderer) return 0;

    // Create a new document
    hoedown_document *doc = hoedown_document_new(renderer, HOEDOWN_EXT_TABLES, 16, 0, NULL, NULL);
    if (!doc) {
        free(renderer);
        return 0;
    }

    // Fuzz the functions
    fuzz_hoedown_document_render_inline(doc, Data, Size);
    fuzz_hoedown_document_link_inline_attr(doc);
    fuzz_hoedown_document_render(doc, Data, Size);

    // Clean up
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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    