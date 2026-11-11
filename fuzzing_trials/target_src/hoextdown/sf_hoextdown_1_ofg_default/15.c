#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/document.h"
#include "/src/hoextdown/src/buffer.h"
#include "/src/hoextdown/src/html.h"

// Define a dummy user block function
static void dummy_user_block_15(hoedown_buffer *ob, const hoedown_buffer *text, void *opaque) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize hoedown_document and hoedown_buffer
    hoedown_document *doc;
    hoedown_buffer *buf;

    // Create a renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);

    // Create a hoedown document with the correct number of arguments
    doc = hoedown_document_new(renderer, 0, 16, 0, dummy_user_block_15, NULL);

    // Allocate a hoedown buffer
    buf = hoedown_buffer_new(64);

    // Ensure the data is not empty before rendering
    if (size > 0) {
        // Call the function-under-test
        hoedown_document_render(doc, buf, data, size);
    }

    // Clean up
    hoedown_buffer_free(buf);
    hoedown_document_free(doc);
    hoedown_html_renderer_free(renderer);

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
