#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/document.h"
#include "/src/hoextdown/src/buffer.h"
#include "/src/hoextdown/src/html.h"

// Define default values for the additional arguments required by hoedown_document_new
#define DEFAULT_EXTENSIONS 0
#define DEFAULT_MAX_NESTING 16
#define DEFAULT_ATTR_ACTIVATION 0
#define DEFAULT_USER_BLOCK NULL
#define DEFAULT_META_BUFFER NULL

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Initialize hoedown_renderer and hoedown_buffer
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);
    hoedown_document *document = hoedown_document_new(renderer, DEFAULT_EXTENSIONS, DEFAULT_MAX_NESTING, DEFAULT_ATTR_ACTIVATION, DEFAULT_USER_BLOCK, DEFAULT_META_BUFFER);
    hoedown_buffer *buffer = hoedown_buffer_new(64);

    // Ensure that the data is not NULL and size is greater than 0
    if (data != NULL && size > 0) {
        // Call the function-under-test
        hoedown_document_render(document, buffer, data, size);
    }

    // Clean up
    hoedown_buffer_free(buffer);
    hoedown_document_free(document);
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
