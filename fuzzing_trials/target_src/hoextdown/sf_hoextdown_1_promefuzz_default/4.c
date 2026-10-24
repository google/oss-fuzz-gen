// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_html_renderer_free at html.c:1185:1 in html.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_html_renderer_free at html.c:1185:1 in html.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_buffer_free at buffer.c:81:1 in buffer.h
// hoedown_html_renderer_free at html.c:1185:1 in html.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "html.h"
#include "document.h"
#include "buffer.h"

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Step 1: Prepare environment
    size_t unit_size = 64;
    hoedown_buffer *buf1 = hoedown_buffer_new(unit_size);
    if (!buf1) return 0;

    // Step 2: Invoke hoedown_buffer_put
    hoedown_buffer_put(buf1, Data, Size);

    // Step 3: Invoke hoedown_html_renderer_new
    hoedown_html_flags render_flags = HOEDOWN_HTML_ESCAPE;
    int nesting_level = 16;
    hoedown_renderer *renderer = hoedown_html_renderer_new(render_flags, nesting_level);
    if (!renderer) {
        hoedown_buffer_free(buf1);
        return 0;
    }

    // Step 4: Create additional buffers
    hoedown_buffer *buf2 = hoedown_buffer_new(unit_size);
    hoedown_buffer *buf3 = hoedown_buffer_new(unit_size);
    if (!buf2 || !buf3) {
        hoedown_html_renderer_free(renderer);
        hoedown_buffer_free(buf1);
        if (buf2) hoedown_buffer_free(buf2);
        if (buf3) hoedown_buffer_free(buf3);
        return 0;
    }

    // Step 5: Invoke hoedown_document_new
    hoedown_extensions extensions = HOEDOWN_EXT_FENCED_CODE;
    size_t max_nesting = 16;
    uint8_t attr_activation = 0;
    hoedown_user_block user_block = NULL;
    hoedown_buffer *meta = NULL;
    hoedown_document *doc = hoedown_document_new(renderer, extensions, max_nesting, attr_activation, user_block, meta);
    if (!doc) {
        hoedown_html_renderer_free(renderer);
        hoedown_buffer_free(buf1);
        hoedown_buffer_free(buf2);
        hoedown_buffer_free(buf3);
        return 0;
    }

    // Step 6: Invoke hoedown_document_render
    hoedown_document_render(doc, buf2, Data, Size);

    // Step 7: Cleanup
    hoedown_buffer_free(buf1);
    hoedown_document_free(doc);
    hoedown_buffer_free(buf2);
    hoedown_buffer_free(buf3);
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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    