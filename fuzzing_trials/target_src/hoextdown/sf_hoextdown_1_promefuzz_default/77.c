// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_link_inline_attr at document.c:4279:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "html.h"
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
static int dummy_autolink(hoedown_buffer *ob, const hoedown_buffer *link, hoedown_autolink_type type, const hoedown_renderer_data *data) { return 0; }
static int dummy_codespan(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *attr, const hoedown_renderer_data *data) { return 0; }
static int dummy_double_emphasis(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 0; }
static int dummy_emphasis(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 0; }
static int dummy_underline(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 0; }
static int dummy_highlight(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 0; }
static int dummy_quote(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 0; }
static int dummy_image(hoedown_buffer *ob, const hoedown_buffer *link, const hoedown_buffer *title, const hoedown_buffer *alt, const hoedown_buffer *attr, const hoedown_renderer_data *data) { return 0; }
static int dummy_linebreak(hoedown_buffer *ob, const hoedown_renderer_data *data) { return 0; }
static int dummy_link(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *link, const hoedown_buffer *title, const hoedown_buffer *attr, const hoedown_renderer_data *data) { return 0; }
static int dummy_triple_emphasis(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 0; }
static int dummy_strikethrough(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 0; }
static int dummy_superscript(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 0; }
static int dummy_footnote_ref(hoedown_buffer *ob, unsigned int num, const hoedown_renderer_data *data) { return 0; }
static int dummy_math(hoedown_buffer *ob, const hoedown_buffer *text, int displaymode, const hoedown_renderer_data *data) { return 0; }
static int dummy_raw_html(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) { return 0; }
static void dummy_entity(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) {}
static void dummy_normal_text(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) {}
static void dummy_doc_header(hoedown_buffer *ob, int inline_render, const hoedown_renderer_data *data) {}
static void dummy_doc_footer(hoedown_buffer *ob, int inline_render, const hoedown_renderer_data *data) {}

int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a dummy renderer
    hoedown_renderer renderer = {
        .blockcode = dummy_blockcode,
        .blockquote = dummy_blockquote,
        .header = dummy_header,
        .hrule = dummy_hrule,
        .list = dummy_list,
        .listitem = dummy_listitem,
        .paragraph = dummy_paragraph,
        .table = dummy_table,
        .table_header = dummy_table_header,
        .table_body = dummy_table_body,
        .table_row = dummy_table_row,
        .table_cell = dummy_table_cell,
        .footnotes = dummy_footnotes,
        .footnote_def = dummy_footnote_def,
        .blockhtml = dummy_blockhtml,
        .autolink = dummy_autolink,
        .codespan = dummy_codespan,
        .double_emphasis = dummy_double_emphasis,
        .emphasis = dummy_emphasis,
        .underline = dummy_underline,
        .highlight = dummy_highlight,
        .quote = dummy_quote,
        .image = dummy_image,
        .linebreak = dummy_linebreak,
        .link = dummy_link,
        .triple_emphasis = dummy_triple_emphasis,
        .strikethrough = dummy_strikethrough,
        .superscript = dummy_superscript,
        .footnote_ref = dummy_footnote_ref,
        .math = dummy_math,
        .raw_html = dummy_raw_html,
        .entity = dummy_entity,
        .normal_text = dummy_normal_text,
        .doc_header = dummy_doc_header,
        .doc_footer = dummy_doc_footer
    };

    // Create a new buffer
    hoedown_buffer *output_buffer = hoedown_buffer_new(64);
    if (!output_buffer) return 0;

    // Create a new document
    hoedown_document *document = hoedown_document_new(&renderer, HOEDOWN_EXT_FENCED_CODE, 16, 0, NULL, NULL);
    if (!document) {
        hoedown_buffer_free(output_buffer);
        return 0;
    }

    // Render inline markdown
    hoedown_document_render_inline(document, output_buffer, Data, Size);

    // Retrieve link inline attributes
    const hoedown_buffer *link_attr = hoedown_document_link_inline_attr(document);
    if (link_attr) {
        // Do something with link_attr if needed
    }

    // Render full markdown document
    hoedown_document_render(document, output_buffer, Data, Size);

    // Clean up
    hoedown_document_free(document);
    hoedown_buffer_free(output_buffer);

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

        LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    