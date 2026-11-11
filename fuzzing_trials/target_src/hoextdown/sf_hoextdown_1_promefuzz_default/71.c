// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
// hoedown_buffer_printf at buffer.c:238:1 in buffer.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "document.h"
#include "buffer.h"

static void dummy_blockcode(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *lang, const hoedown_buffer *attr, const hoedown_renderer_data *data) {}
static void dummy_paragraph(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, const hoedown_renderer_data *data) {}
static void dummy_doc_header(hoedown_buffer *ob, int inline_render, const hoedown_renderer_data *data) {}
static void dummy_doc_footer(hoedown_buffer *ob, int inline_render, const hoedown_renderer_data *data) {}

int LLVMFuzzerTestOneInput_71(const uint8_t *Data, size_t Size) {
    // Initialize a hoedown_buffer
    hoedown_buffer *buf = hoedown_buffer_new(64);
    if (!buf) return 0;

    // Initialize a hoedown_renderer
    hoedown_renderer renderer = {
        .blockcode = dummy_blockcode,
        .paragraph = dummy_paragraph,
        .doc_header = dummy_doc_header,
        .doc_footer = dummy_doc_footer,
    };

    // Initialize a hoedown_document
    hoedown_document *doc = hoedown_document_new(&renderer, HOEDOWN_EXT_AUTOLINK, 16, 0, NULL, NULL);
    if (!doc) {
        hoedown_buffer_free(buf);
        return 0;
    }

    // Invoke hoedown_document_render_inline
    hoedown_document_render_inline(doc, buf, Data, Size);

    // Invoke hoedown_buffer_put
    hoedown_buffer_put(buf, Data, Size);

    // Invoke hoedown_buffer_printf
    hoedown_buffer_printf(buf, "Formatted number: %d", (int)Size);

    // Cleanup
    hoedown_document_free(doc);
    hoedown_buffer_free(buf);

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

        LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    