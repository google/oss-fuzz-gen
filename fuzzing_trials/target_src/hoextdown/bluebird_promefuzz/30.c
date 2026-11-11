#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "document.h"

// Dummy callback implementations for the renderer
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

static int dummy_autolink(hoedown_buffer *ob, const hoedown_buffer *link, hoedown_autolink_type type, const hoedown_renderer_data *data) { return 1; }
static int dummy_codespan(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *attr, const hoedown_renderer_data *data) { return 1; }
static int dummy_double_emphasis(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 1; }
static int dummy_emphasis(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 1; }
static int dummy_underline(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 1; }
static int dummy_highlight(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 1; }
static int dummy_quote(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 1; }
static int dummy_image(hoedown_buffer *ob, const hoedown_buffer *link, const hoedown_buffer *title, const hoedown_buffer *alt, const hoedown_buffer *attr, const hoedown_renderer_data *data) { return 1; }
static int dummy_linebreak(hoedown_buffer *ob, const hoedown_renderer_data *data) { return 1; }
static int dummy_link(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *link, const hoedown_buffer *title, const hoedown_buffer *attr, const hoedown_renderer_data *data) { return 1; }
static int dummy_triple_emphasis(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 1; }
static int dummy_strikethrough(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 1; }
static int dummy_superscript(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) { return 1; }
static int dummy_footnote_ref(hoedown_buffer *ob, unsigned int num, const hoedown_renderer_data *data) { return 1; }
static int dummy_math(hoedown_buffer *ob, const hoedown_buffer *text, int displaymode, const hoedown_renderer_data *data) { return 1; }
static int dummy_raw_html(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) { return 1; }

static void dummy_entity(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) {}
static void dummy_normal_text(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) {}

static void dummy_doc_header(hoedown_buffer *ob, int inline_render, const hoedown_renderer_data *data) {}
static void dummy_doc_footer(hoedown_buffer *ob, int inline_render, const hoedown_renderer_data *data) {}

static void dummy_user_block(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) {}

static void dummy_ref(hoedown_buffer *orig, const hoedown_renderer_data *data) {}
static void dummy_footnote_ref_def(hoedown_buffer *orig, const hoedown_renderer_data *data) {}

static void *dummy_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

static void dummy_free(void *ptr) {
    free(ptr);
}

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    hoedown_renderer renderer = {
        .opaque = NULL,
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
        .doc_footer = dummy_doc_footer,
        .user_block = dummy_user_block,
        .ref = dummy_ref,
        .footnote_ref_def = dummy_footnote_ref_def
    };

    // Create a dummy user block and meta buffer
    hoedown_user_block user_block = NULL;
    hoedown_buffer meta = {0};

    // Allocate memory for hoedown_document using a known size or a factory function
    hoedown_document *doc = hoedown_document_new(&renderer, HOEDOWN_EXT_TABLES | HOEDOWN_EXT_FOOTNOTES, 16, 0, user_block, &meta);
    if (!doc) {
        return 0;
    }

    hoedown_buffer ob = {
        .data = (uint8_t *)malloc(Size),
        .size = 0,
        .asize = Size,
        .unit = 64,
        .data_realloc = dummy_realloc,
        .data_free = dummy_free,
        .buffer_free = dummy_free
    };

    if (!ob.data) {
        hoedown_document_free(doc);
        return 0;
    }

    hoedown_document_render(doc, &ob, Data, Size);
    hoedown_document_render_inline(doc, &ob, Data, Size);
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function hoedown_document_list_depth with hoedown_document_is_escaped
    int list_depth = hoedown_document_is_escaped(doc);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    hoedown_header_type header_type = hoedown_document_header_type(doc);
    const hoedown_buffer *footnote_id = hoedown_document_footnote_id(doc);
    const hoedown_buffer *ol_numeral = hoedown_document_ol_numeral(doc);

    (void)list_depth;
    (void)header_type;
    (void)footnote_id;
    (void)ol_numeral;

    free(ob.data);
    hoedown_document_free(doc);
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
