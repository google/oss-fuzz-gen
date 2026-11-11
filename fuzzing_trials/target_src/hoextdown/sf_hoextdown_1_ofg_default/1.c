#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/document.h"
#include "/src/hoextdown/src/buffer.h"
#include "/src/hoextdown/src/html.h"

// Define a dummy user block function
void dummy_user_block_1(const hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *lang, void *opaque) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Initialize hoedown document and buffer
    hoedown_document *doc = NULL;
    hoedown_buffer *buf = NULL;

    // Create a hoedown renderer
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);

    // Allocate memory for hoedown buffer
    buf = hoedown_buffer_new(64);

    // Ensure the renderer and buffer are not NULL
    if (renderer == NULL || buf == NULL) {
        if (renderer != NULL) {
            hoedown_html_renderer_free(renderer);
        }
        if (buf != NULL) {
            hoedown_buffer_free(buf);
        }
        return 0;
    }

    // Allocate memory for hoedown document with the correct number of arguments
    doc = hoedown_document_new(renderer, 0, 16, 0, dummy_user_block_1, buf);

    // Ensure the document is not NULL
    if (doc == NULL) {
        hoedown_html_renderer_free(renderer);
        hoedown_buffer_free(buf);
        return 0;
    }

    // Call the function-under-test
    hoedown_document_render(doc, buf, data, size);

    // Free the allocated resources
    hoedown_document_free(doc);
    hoedown_buffer_free(buf);
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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
