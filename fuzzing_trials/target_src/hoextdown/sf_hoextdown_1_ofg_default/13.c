#include <stdint.h>
#include <stdlib.h>
#include "/src/hoextdown/src/document.h"
#include "/src/hoextdown/src/buffer.h"
#include "/src/hoextdown/src/html.h" // Include the header for HTML renderer functions

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Initialize hoedown document and buffer
    hoedown_document *doc;
    hoedown_buffer *output_buffer;

    // Create a renderer with default flags
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);

    // Check if renderer was created successfully
    if (!renderer) {
        return 0; // If renderer creation fails, exit early
    }

    // Create a new document with required parameters
    doc = hoedown_document_new(renderer, 0, 16, 0, NULL, NULL);

    // Check if document was created successfully
    if (!doc) {
        hoedown_html_renderer_free(renderer);
        return 0; // If document creation fails, exit early
    }

    // Create a new buffer for output
    output_buffer = hoedown_buffer_new(64);

    // Check if buffer was created successfully
    if (!output_buffer) {
        hoedown_document_free(doc);
        hoedown_html_renderer_free(renderer);
        return 0; // If buffer creation fails, exit early
    }

    // Call the function-under-test
    hoedown_document_render(doc, output_buffer, data, size);

    // Clean up
    hoedown_buffer_free(output_buffer);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
