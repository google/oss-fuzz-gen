#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/hoextdown/src/document.h"
#include "/src/hoextdown/src/buffer.h"
#include "/src/hoextdown/src/html.h"  // Include for hoedown_renderer

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Create a renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);

    // Initialize hoedown document and buffer
    hoedown_document *document = hoedown_document_new(renderer, 0, 16, 0, NULL, NULL);
    hoedown_buffer *buffer = hoedown_buffer_new(64);

    if (document == NULL || buffer == NULL) {
        // Clean up and return if initialization failed
        if (document != NULL) hoedown_document_free(document);
        if (buffer != NULL) hoedown_buffer_free(buffer);
        if (renderer != NULL) hoedown_html_renderer_free(renderer);
        return 0;
    }

    // Call the function-under-test
    hoedown_document_render(document, buffer, data, size);

    // Clean up
    hoedown_document_free(document);
    hoedown_buffer_free(buffer);
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
