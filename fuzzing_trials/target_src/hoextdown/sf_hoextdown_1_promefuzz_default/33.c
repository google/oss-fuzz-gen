// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_link_inline_attr at document.c:4279:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "html.h"
#include "document.h"

static void fuzz_hoedown_document_render_inline(hoedown_document *doc, const uint8_t *data, size_t size) {
    hoedown_buffer ob;
    memset(&ob, 0, sizeof(ob));
    ob.unit = 64; // Set a non-zero unit size for buffer resizing

    // Allocate memory for the buffer's data field
    ob.data = (uint8_t *)malloc(ob.unit);
    if (!ob.data) return;
    ob.asize = ob.unit;

    hoedown_document_render_inline(doc, &ob, data, size);

    free(ob.data);
}

static void fuzz_hoedown_document_link_inline_attr(hoedown_document *doc) {
    const hoedown_buffer *attr = hoedown_document_link_inline_attr(doc);
    // Use the attribute buffer if needed
    (void)attr; // Prevent unused variable warning
}

static void fuzz_hoedown_document_render(hoedown_document *doc, const uint8_t *data, size_t size) {
    hoedown_buffer ob;
    memset(&ob, 0, sizeof(ob));
    ob.unit = 64; // Set a non-zero unit size for buffer resizing

    // Allocate memory for the buffer's data field
    ob.data = (uint8_t *)malloc(ob.unit);
    if (!ob.data) return;
    ob.asize = ob.unit;

    hoedown_document_render(doc, &ob, data, size);

    free(ob.data);
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(HOEDOWN_HTML_USE_XHTML, 16);
    if (!renderer) return 0;

    // Initialize renderer function pointers to prevent NULL dereference
    renderer->blockcode = NULL; // Ensure all function pointers are initialized appropriately

    // Create a document
    hoedown_document *doc = hoedown_document_new(renderer, HOEDOWN_EXT_TABLES, 16, 1, NULL, NULL);
    if (!doc) {
        free(renderer);
        return 0;
    }

    // Check if the renderer blockcode callback is non-NULL before rendering
    if (renderer->blockcode) {
        fuzz_hoedown_document_render_inline(doc, Data, Size);
        fuzz_hoedown_document_link_inline_attr(doc);
        fuzz_hoedown_document_render(doc, Data, Size);
    }

    // Cleanup
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

        LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    