// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "document.h"
#include "buffer.h"

static void dummy_blockcode(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *lang, const hoedown_buffer *attr, const hoedown_renderer_data *data) {
    // Dummy implementation for blockcode
}

static void dummy_blockquote(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) {
    // Dummy implementation for blockquote
}

static void dummy_header(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *attr, int level, const hoedown_renderer_data *data) {
    // Dummy implementation for header
}

static void dummy_hrule(hoedown_buffer *ob, const hoedown_renderer_data *data) {
    // Dummy implementation for hrule
}

static void dummy_list(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, hoedown_list_flags flags, const hoedown_renderer_data *data) {
    // Dummy implementation for list
}

static void dummy_listitem(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, hoedown_list_flags *flags, const hoedown_renderer_data *data) {
    // Dummy implementation for listitem
}

static hoedown_renderer *create_dummy_renderer() {
    hoedown_renderer *renderer = (hoedown_renderer *)malloc(sizeof(hoedown_renderer));
    memset(renderer, 0, sizeof(hoedown_renderer));
    renderer->blockcode = dummy_blockcode;
    renderer->blockquote = dummy_blockquote;
    renderer->header = dummy_header;
    renderer->hrule = dummy_hrule;
    renderer->list = dummy_list;
    renderer->listitem = dummy_listitem;
    return renderer;
}

static void free_dummy_renderer(hoedown_renderer *renderer) {
    free(renderer);
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize buffers
    hoedown_buffer *input_buffer = hoedown_buffer_new(64);
    hoedown_buffer *output_buffer = hoedown_buffer_new(64);

    // Copy data to input buffer
    hoedown_buffer_put(input_buffer, Data, Size);

    // Create dummy renderer
    hoedown_renderer *renderer = create_dummy_renderer();

    // Create a document
    hoedown_document *document = hoedown_document_new(
        renderer,
        HOEDOWN_EXT_TABLES | HOEDOWN_EXT_FENCED_CODE,
        16,
        0,
        NULL,
        NULL
    );

    // Render document
    hoedown_document_render(document, output_buffer, input_buffer->data, input_buffer->size);

    // Render inline
    hoedown_document_render_inline(document, output_buffer, input_buffer->data, input_buffer->size);

    // Clean up
    hoedown_document_free(document);
    hoedown_buffer_free(input_buffer);
    hoedown_buffer_free(output_buffer);
    free_dummy_renderer(renderer);

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
    