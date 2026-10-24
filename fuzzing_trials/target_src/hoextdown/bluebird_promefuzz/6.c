#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/hoextdown/src/buffer.h"
#include "html.h"
#include "document.h"

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // 1. Create a new buffer
    size_t buffer_unit = 64; // Arbitrary non-zero unit size
    hoedown_buffer *buf = hoedown_buffer_new(buffer_unit);
    if (!buf) {
        return 0;
    }

    // 2. Put data into the buffer
    hoedown_buffer_put(buf, Data, Size);

    // 3. Create a new HTML renderer
    hoedown_html_flags render_flags = HOEDOWN_HTML_USE_XHTML;
    int nesting_level = 16; // Arbitrary nesting level
    hoedown_renderer *renderer = hoedown_html_renderer_new(render_flags, nesting_level);
    if (!renderer) {
        hoedown_buffer_free(buf);
        return 0;
    }

    // 4. Create a new output buffer
    hoedown_buffer *output_buf = hoedown_buffer_new(buffer_unit);
    if (!output_buf) {
        hoedown_buffer_free(buf);
        free(renderer);
        return 0;
    }

    // 5. Create a new meta buffer
    hoedown_buffer *meta_buf = hoedown_buffer_new(buffer_unit);
    if (!meta_buf) {
        hoedown_buffer_free(buf);
        hoedown_buffer_free(output_buf);
        free(renderer);
        return 0;
    }

    // 6. Create a new document
    hoedown_extensions extensions = HOEDOWN_EXT_TABLES | HOEDOWN_EXT_FENCED_CODE;
    size_t max_nesting = 16; // Arbitrary non-zero max nesting
    uint8_t attr_activation = 1; // Enable attributes
    hoedown_user_block user_block = NULL; // No user block
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of hoedown_document_new
    hoedown_document *doc = hoedown_document_new(renderer, HOEDOWN_EXT_SPECIAL_ATTRIBUTE, max_nesting, attr_activation, user_block, meta_buf);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (!doc) {
        hoedown_buffer_free(buf);
        hoedown_buffer_free(output_buf);
        hoedown_buffer_free(meta_buf);
        free(renderer);
        return 0;
    }

    // 7. Render the document
    hoedown_document_render(doc, output_buf, Data, Size);

    // 8. Cleanup
    hoedown_document_free(doc);
    hoedown_buffer_free(meta_buf);
    hoedown_buffer_free(output_buf);
    hoedown_buffer_free(buf);
    hoedown_html_renderer_free(renderer); // Properly free the renderer

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
