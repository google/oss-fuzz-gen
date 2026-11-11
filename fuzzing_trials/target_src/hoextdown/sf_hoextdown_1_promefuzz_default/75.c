// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_link_inline_attr at document.c:4279:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
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
#include "buffer.h"

static void dummy_blockcode(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *lang, const hoedown_buffer *attr, const hoedown_renderer_data *data) {}
static void dummy_blockquote(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) {}
static void dummy_header(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *attr, int level, const hoedown_renderer_data *data) {}
static void dummy_hrule(hoedown_buffer *ob, const hoedown_renderer_data *data) {}
static void dummy_paragraph(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, const hoedown_renderer_data *data) {}
static void dummy_doc_header(hoedown_buffer *ob, int inline_render, const hoedown_renderer_data *data) {}
static void dummy_doc_footer(hoedown_buffer *ob, int inline_render, const hoedown_renderer_data *data) {}

int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize renderer with dummy functions
    hoedown_renderer renderer = {
        .blockcode = dummy_blockcode,
        .blockquote = dummy_blockquote,
        .header = dummy_header,
        .hrule = dummy_hrule,
        .paragraph = dummy_paragraph,
        .doc_header = dummy_doc_header,
        .doc_footer = dummy_doc_footer
    };

    // Create a new HTML renderer
    hoedown_renderer *html_renderer = hoedown_html_renderer_new(HOEDOWN_HTML_ESCAPE, 16);
    if (!html_renderer) return 0;

    // Create a new document
    hoedown_document *doc = hoedown_document_new(html_renderer, HOEDOWN_EXT_AUTOLINK, 16, 0, NULL, NULL);
    if (!doc) {
        free(html_renderer);
        return 0;
    }

    // Create a new buffer
    hoedown_buffer *output_buffer = hoedown_buffer_new(64);
    if (!output_buffer) {
        hoedown_document_free(doc);
        free(html_renderer);
        return 0;
    }

    // Render inline markdown
    hoedown_document_render_inline(doc, output_buffer, Data, Size);

    // Retrieve link inline attributes
    const hoedown_buffer *link_attr = hoedown_document_link_inline_attr(doc);

    // Render full markdown document
    hoedown_document_render(doc, output_buffer, Data, Size);

    // Clean up
    hoedown_buffer_free(output_buffer);
    hoedown_document_free(doc);
    free(html_renderer);

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

        LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    