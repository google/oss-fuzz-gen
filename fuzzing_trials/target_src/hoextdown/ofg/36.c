#include <stdint.h>
#include <stddef.h>
#include "/src/hoextdown/src/document.h" // Correct path for hoedown_document and related functions
#include "/src/hoextdown/src/buffer.h"   // Include buffer.h for hoedown_buffer
#include "/src/hoextdown/src/html.h"     // Include html.h for hoedown_html_renderer_new and hoedown_html_renderer_free

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Create a buffer to hold the output
    hoedown_buffer *ob = hoedown_buffer_new(64);

    // Create a renderer (assuming a default renderer is available)
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);

    // Create a new hoedown document with the provided data
    hoedown_document *doc = hoedown_document_new(renderer, 0, 16, 0, NULL, NULL);

    // Ensure that doc is not NULL before proceeding
    if (doc != NULL && ob != NULL) {
        // Use the document with the provided data
        hoedown_document_render(doc, ob, data, size);

        // Free the document after use
        hoedown_document_free(doc);
    }

    // Free the renderer and buffer
    hoedown_html_renderer_free(renderer);
    hoedown_buffer_free(ob);

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
