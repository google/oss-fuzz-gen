// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
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
#include "document.h"
#include "buffer.h"

static void dummy_blockcode(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *lang, const hoedown_buffer *attr, const hoedown_renderer_data *data) {}
static void dummy_blockquote(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) {}
static void dummy_header(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *attr, int level, const hoedown_renderer_data *data) {}
static void dummy_hrule(hoedown_buffer *ob, const hoedown_renderer_data *data) {}
static void dummy_list(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, hoedown_list_flags flags, const hoedown_renderer_data *data) {}
static void dummy_listitem(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, hoedown_list_flags *flags, const hoedown_renderer_data *data) {}
static void dummy_paragraph(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, const hoedown_renderer_data *data) {}
static void dummy_table(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, const hoedown_renderer_data *data) {}
static void dummy_table_header(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) {}
static void dummy_table_body(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) {}
static void dummy_table_row(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) {}
static void dummy_table_cell(hoedown_buffer *ob, const hoedown_buffer *content, hoedown_table_flags flags, const hoedown_renderer_data *data) {}
static void dummy_footnotes(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) {}
static void dummy_footnote_def(hoedown_buffer *ob, const hoedown_buffer *content, unsigned int num, const hoedown_renderer_data *data) {}
static void dummy_blockhtml(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) {}

static hoedown_renderer dummy_renderer = {
    NULL, // opaque
    dummy_blockcode,
    dummy_blockquote,
    dummy_header,
    dummy_hrule,
    dummy_list,
    dummy_listitem,
    dummy_paragraph,
    dummy_table,
    dummy_table_header,
    dummy_table_body,
    dummy_table_row,
    dummy_table_cell,
    dummy_footnotes,
    dummy_footnote_def,
    dummy_blockhtml,
    NULL, // autolink
    NULL, // codespan
    NULL, // double_emphasis
    NULL, // emphasis
    NULL, // underline
    NULL, // highlight
    NULL, // quote
    NULL, // image
    NULL, // linebreak
    NULL, // link
    NULL, // triple_emphasis
    NULL, // strikethrough
    NULL, // superscript
    NULL, // footnote_ref
    NULL, // math
    NULL, // raw_html
    NULL, // entity
    NULL, // normal_text
    NULL, // doc_header
    NULL, // doc_footer
    NULL, // user_block
    NULL, // ref
    NULL  // footnote_ref_def
};

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize a buffer
    hoedown_buffer *buffer = hoedown_buffer_new(64);
    if (!buffer) return 0;

    // Initialize a document
    hoedown_document *document = hoedown_document_new(&dummy_renderer, HOEDOWN_EXT_FOOTNOTES, 16, 1, NULL, NULL);
    if (!document) {
        hoedown_buffer_free(buffer);
        return 0;
    }

    // Fuzz hoedown_buffer_put
    hoedown_buffer_put(buffer, Data, Size);

    // Fuzz hoedown_document_render_inline
    hoedown_document_render_inline(document, buffer, Data, Size);

    // Fuzz hoedown_document_render
    hoedown_document_render(document, buffer, Data, Size);

    // Cleanup
    hoedown_document_free(document);
    hoedown_buffer_free(buffer);

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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    