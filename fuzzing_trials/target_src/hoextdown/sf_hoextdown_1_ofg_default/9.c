#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h"
#include "/src/hoextdown/src/document.h"
#include "/src/hoextdown/src/html.h" // Include the correct header for hoedown_html_renderer_new

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Initialize hoedown_buffer and hoedown_document
    hoedown_buffer *output_buffer = hoedown_buffer_new(64);

    // Create a default renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);

    // Initialize the document with the correct number of arguments
    hoedown_document *document = hoedown_document_new(
        renderer,         // hoedown_renderer
        0,                // hoedown_extensions
        16,               // max_nesting, a reasonable default value
        0,                // attr_activation, assuming default is 0
        NULL,             // hoedown_user_block, assuming no user block is needed
        NULL              // hoedown_buffer *meta, assuming no metadata is needed
    );

    // Ensure the data is not NULL and has a valid size
    if (data == NULL || size == 0) {
        hoedown_buffer_free(output_buffer);
        hoedown_document_free(document);
        hoedown_html_renderer_free(renderer); // Free the renderer
        return 0;
    }

    // Call the function-under-test
    hoedown_document_render(document, output_buffer, data, size);

    // Clean up
    hoedown_buffer_free(output_buffer);
    hoedown_document_free(document);
    hoedown_html_renderer_free(renderer); // Free the renderer

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
