#include <stdint.h>
#include <stdlib.h>
#include "/src/hoextdown/src/document.h"
#include "/src/hoextdown/src/html.h"
#include "/src/hoextdown/src/buffer.h" // Include necessary for hoedown_buffer

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to create a document
    if (size < 1) {
        return 0;
    }

    // Allocate memory for hoedown_renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);
    if (renderer == NULL) {
        return 0;
    }

    // Create a buffer for meta, which is required by hoedown_document_new
    hoedown_buffer *meta = hoedown_buffer_new(64);
    if (meta == NULL) {
        hoedown_html_renderer_free(renderer);
        return 0;
    }

    // Create a document with all required arguments
    hoedown_document *doc = hoedown_document_new(renderer, 0, 16, 0, NULL, meta);

    // Check if the document was created successfully
    if (doc == NULL) {
        hoedown_buffer_free(meta);
        hoedown_html_renderer_free(renderer);
        return 0;
    }

    // Create a buffer to hold the rendered output
    hoedown_buffer *output = hoedown_buffer_new(64);
    if (output == NULL) {
        hoedown_document_free(doc);
        hoedown_buffer_free(meta);
        hoedown_html_renderer_free(renderer);
        return 0;
    }

    // Render the input data into the document
    hoedown_document_render(doc, output, data, size);

    // Clean up
    hoedown_buffer_free(output);
    hoedown_document_free(doc);
    hoedown_buffer_free(meta);
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
