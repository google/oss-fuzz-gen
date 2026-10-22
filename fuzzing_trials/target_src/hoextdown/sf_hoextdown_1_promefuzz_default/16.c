// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "document.h"
#include "buffer.h"

static void dummy_blockcode(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *lang, const hoedown_buffer *attr, const hoedown_renderer_data *data) {
    // Dummy function for blockcode
}

static void dummy_blockquote(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_renderer_data *data) {
    // Dummy function for blockquote
}

static void dummy_header(hoedown_buffer *ob, const hoedown_buffer *text, const hoedown_buffer *attr, int level, const hoedown_renderer_data *data) {
    // Dummy function for header
}

static void dummy_hrule(hoedown_buffer *ob, const hoedown_renderer_data *data) {
    // Dummy function for hrule
}

static void dummy_list(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, hoedown_list_flags flags, const hoedown_renderer_data *data) {
    // Dummy function for list
}

static void dummy_listitem(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, hoedown_list_flags *flags, const hoedown_renderer_data *data) {
    // Dummy function for listitem
}

static void dummy_paragraph(hoedown_buffer *ob, const hoedown_buffer *content, const hoedown_buffer *attr, const hoedown_renderer_data *data) {
    // Dummy function for paragraph
}

static hoedown_renderer *create_dummy_renderer() {
    hoedown_renderer *renderer = (hoedown_renderer *)malloc(sizeof(hoedown_renderer));
    if (!renderer) return NULL;
    memset(renderer, 0, sizeof(hoedown_renderer));
    renderer->blockcode = dummy_blockcode;
    renderer->blockquote = dummy_blockquote;
    renderer->header = dummy_header;
    renderer->hrule = dummy_hrule;
    renderer->list = dummy_list;
    renderer->listitem = dummy_listitem;
    renderer->paragraph = dummy_paragraph;
    return renderer;
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize buffers and document
    hoedown_buffer *output_buffer = hoedown_buffer_new(64);
    hoedown_buffer *meta_buffer = hoedown_buffer_new(64);
    hoedown_renderer *dummy_renderer = create_dummy_renderer();
    if (!output_buffer || !meta_buffer || !dummy_renderer) {
        if (output_buffer) hoedown_buffer_free(output_buffer);
        if (meta_buffer) hoedown_buffer_free(meta_buffer);
        if (dummy_renderer) free(dummy_renderer);
        return 0;
    }

    hoedown_document *doc = hoedown_document_new(
        dummy_renderer,
        HOEDOWN_EXT_TABLES | HOEDOWN_EXT_FOOTNOTES,
        16,
        1,
        NULL,
        meta_buffer
    );

    if (!doc) {
        hoedown_buffer_free(output_buffer);
        hoedown_buffer_free(meta_buffer);
        free(dummy_renderer);
        return 0;
    }

    // Fuzz hoedown_buffer_put
    hoedown_buffer_put(output_buffer, Data, Size);

    // Fuzz hoedown_document_render_inline
    hoedown_document_render_inline(doc, output_buffer, Data, Size);

    // Fuzz hoedown_document_render
    hoedown_document_render(doc, output_buffer, Data, Size);

    // Cleanup
    hoedown_document_free(doc);
    hoedown_buffer_free(output_buffer);
    hoedown_buffer_free(meta_buffer);
    free(dummy_renderer);

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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    