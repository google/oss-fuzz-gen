#include <stdint.h>
#include <stddef.h>
#include "/src/hoextdown/src/document.h"
#include "/src/hoextdown/src/buffer.h"

// Dummy renderer and user block for initialization
static void dummy_renderer_block(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) {
    // Dummy implementation
}

static void dummy_user_block_16(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_renderer_data *data) {
    // Dummy implementation
}

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Initialize hoedown_renderer
    hoedown_renderer renderer = {
        .blockcode = dummy_renderer_block,
        .blockquote = dummy_renderer_block,
        .header = dummy_renderer_block,
        .hrule = dummy_renderer_block,
        .list = dummy_renderer_block,
        .listitem = dummy_renderer_block,
        .paragraph = dummy_renderer_block,
        .table = dummy_renderer_block,
        .table_row = dummy_renderer_block,
        .table_cell = dummy_renderer_block,
    };

    // Initialize hoedown_document and hoedown_buffer
    hoedown_document *doc = hoedown_document_new(&renderer, 0, 16, 0, dummy_user_block_16, NULL);
    hoedown_buffer *buffer = hoedown_buffer_new(64);

    // Ensure data is not NULL and size is greater than 0
    if (data != NULL && size > 0) {
        // Call the function-under-test
        hoedown_document_render(doc, buffer, data, size);
    }

    // Clean up
    hoedown_buffer_free(buffer);
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
