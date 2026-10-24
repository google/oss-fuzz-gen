#include <stdint.h>
#include <stdlib.h>
#include "/src/hoextdown/src/document.h"
#include "/src/hoextdown/src/buffer.h"
#include "/src/hoextdown/src/html.h"  // Include the correct header for HTML renderer

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Initialize hoedown document and buffer
    hoedown_document *document;
    hoedown_buffer *output_buffer;
    hoedown_renderer *renderer;

    // Allocate memory for the output buffer
    output_buffer = hoedown_buffer_new(64);

    // Create a renderer
    renderer = hoedown_html_renderer_new(0, 0);

    // Create a document with the renderer
    // Updated to include all required parameters
    document = hoedown_document_new(renderer, 0, 16, 0, NULL, NULL);

    // Call the function-under-test
    hoedown_document_render(document, output_buffer, data, size);

    // Clean up
    hoedown_document_free(document);
    hoedown_html_renderer_free(renderer);
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
