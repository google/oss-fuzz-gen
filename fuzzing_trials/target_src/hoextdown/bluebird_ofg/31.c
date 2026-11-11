#include <sys/stat.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "document.h"
#include "/src/hoextdown/src/buffer.h"

// Dummy renderer and user block for demonstration purposes
void dummy_blockcode(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *lang, void *opaque) {
    // Dummy implementation
}

void dummy_blockquote(hoedown_buffer *ob, const hoedown_buffer *content, void *opaque) {
    // Dummy implementation
}

void dummy_header(hoedown_buffer *ob, const hoedown_buffer *content, int level, void *opaque) {
    // Dummy implementation
}

hoedown_renderer dummy_renderer = {
    /* Block level callbacks */
    dummy_blockcode,   // blockcode
    dummy_blockquote,  // blockquote
    NULL,              // blockhtml
    dummy_header,      // header
    NULL,              // hrule
    NULL,              // list
    NULL,              // listitem
    NULL,              // paragraph
    NULL,              // table
    NULL,              // table_row
    NULL,              // table_cell

    /* Span level callbacks */
    NULL,              // autolink
    NULL,              // codespan
    NULL,              // double_emphasis
    NULL,              // emphasis
    NULL,              // image
    NULL,              // linebreak
    NULL,              // link
    NULL,              // raw_html_tag
    NULL,              // triple_emphasis
    NULL,              // strikethrough
    NULL,              // superscript

    /* Low level callbacks */
    NULL,              // entity
    NULL,              // normal_text

    /* Renderer data */
    NULL               // opaque
};

hoedown_user_block dummy_user_block = {
    NULL,  // opaque
    NULL   // block
};

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure the data is not NULL and size is greater than 0
    if (data == NULL || size == 0) {
        return 0;
    }

    // Initialize the hoedown document with appropriate arguments
    hoedown_document *doc = hoedown_document_new(
        &dummy_renderer,   // renderer
        0,                 // extensions
        16,                // max_nesting
        0,                 // attr_activation
        dummy_user_block,  // user_block
        NULL               // meta
    );

    if (doc == NULL) {
        return 0; // Return early if document creation fails
    }

    // Create a hoedown buffer for the output
    hoedown_buffer *output_buffer = hoedown_buffer_new(64);

    if (output_buffer == NULL) {
        hoedown_document_free(doc);
        return 0; // Return early if buffer creation fails
    }

    // Call the function-under-test
    hoedown_document_render(doc, output_buffer, data, size);

    // Clean up
    hoedown_buffer_free(output_buffer);
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
