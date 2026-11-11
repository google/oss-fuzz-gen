// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
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
static void dummy_user_block(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) {}
static void dummy_ref(hoedown_buffer *orig, const hoedown_renderer_data *data) {}
static void dummy_footnote_ref_def(hoedown_buffer *orig, const hoedown_renderer_data *data) {}

static hoedown_renderer *create_dummy_renderer() {
    hoedown_renderer *renderer = (hoedown_renderer *)malloc(sizeof(hoedown_renderer));
    memset(renderer, 0, sizeof(hoedown_renderer));
    renderer->blockcode = dummy_blockcode;
    renderer->blockquote = dummy_blockquote;
    renderer->header = dummy_header;
    renderer->hrule = dummy_hrule;
    renderer->list = dummy_list;
    renderer->listitem = dummy_listitem;
    renderer->paragraph = dummy_paragraph;
    renderer->table = dummy_table;
    renderer->table_header = dummy_table_header;
    renderer->table_body = dummy_table_body;
    renderer->table_row = dummy_table_row;
    renderer->table_cell = dummy_table_cell;
    renderer->footnotes = dummy_footnotes;
    renderer->footnote_def = dummy_footnote_def;
    renderer->blockhtml = dummy_blockhtml;
    renderer->autolink = dummy_autolink;
    renderer->codespan = dummy_codespan;
    renderer->double_emphasis = dummy_double_emphasis;
    renderer->emphasis = dummy_emphasis;
    renderer->underline = dummy_underline;
    renderer->highlight = dummy_highlight;
    renderer->quote = dummy_quote;
    renderer->image = dummy_image;
    renderer->linebreak = dummy_linebreak;
    renderer->link = dummy_link;
    renderer->triple_emphasis = dummy_triple_emphasis;
    renderer->strikethrough = dummy_strikethrough;
    renderer->superscript = dummy_superscript;
    renderer->footnote_ref = dummy_footnote_ref;
    renderer->math = dummy_math;
    renderer->raw_html = dummy_raw_html;
    renderer->entity = dummy_entity;
    renderer->normal_text = dummy_normal_text;
    renderer->doc_header = dummy_doc_header;
    renderer->doc_footer = dummy_doc_footer;
    renderer->user_block = dummy_user_block;
    renderer->ref = dummy_ref;
    renderer->footnote_ref_def = dummy_footnote_ref_def;
    return renderer;
}

static void free_dummy_renderer(hoedown_renderer *renderer) {
    free(renderer);
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    // Prepare environment
    hoedown_buffer *output_buffer = hoedown_buffer_new(64);
    hoedown_buffer *meta_buffer = hoedown_buffer_new(64);
    hoedown_renderer *renderer = create_dummy_renderer();
    hoedown_document *document = hoedown_document_new(renderer, HOEDOWN_EXT_AUTOLINK, 16, 0, NULL, meta_buffer);

    // Fuzz hoedown_buffer_put
    hoedown_buffer_put(output_buffer, Data, Size);

    // Fuzz hoedown_document_render_inline
    hoedown_document_render_inline(document, output_buffer, Data, Size);

    // Fuzz hoedown_document_render
    hoedown_document_render(document, output_buffer, Data, Size);

    // Cleanup
    hoedown_document_free(document);
    free_dummy_renderer(renderer);
    hoedown_buffer_free(output_buffer);
    hoedown_buffer_free(meta_buffer);

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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    