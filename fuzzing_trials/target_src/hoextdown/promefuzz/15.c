// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_html_toc_renderer_new at html.c:1040:1 in html.h
// hoedown_html_renderer_new at html.c:1110:1 in html.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_document_render_inline at document.c:4186:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
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
#include "html.h"

static void fuzz_hoedown_document_render(const uint8_t *Data, size_t Size) {
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);
    if (!renderer) return;

    hoedown_document *doc = hoedown_document_new(renderer, 0, 1, 0, NULL, NULL);
    if (!doc) {
        free(renderer);
        return;
    }

    hoedown_buffer ob;
    ob.data = malloc(Size);
    if (!ob.data) {
        hoedown_document_free(doc);
        free(renderer);
        return;
    }
    ob.size = 0;
    ob.asize = Size;
    ob.unit = 64;
    ob.data_realloc = realloc;
    ob.data_free = free;
    ob.buffer_free = free;

    hoedown_document_render(doc, &ob, Data, Size);

    free(ob.data);
    hoedown_document_free(doc);
    free(renderer);
}

static void fuzz_hoedown_document_new(const uint8_t *Data, size_t Size) {
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);
    if (!renderer) return;

    hoedown_document *doc = hoedown_document_new(renderer, 0, 1, 0, NULL, NULL);
    if (doc) {
        hoedown_document_free(doc);
    }
    free(renderer);
}

static void fuzz_hoedown_html_toc_renderer_new(const uint8_t *Data, size_t Size) {
    int nesting_level = Size > 0 ? Data[0] % 10 : 1;
    hoedown_renderer *renderer = hoedown_html_toc_renderer_new(nesting_level);
    if (renderer) {
        free(renderer);
    }
}

static void fuzz_hoedown_document_render_inline(const uint8_t *Data, size_t Size) {
    hoedown_renderer *renderer = hoedown_html_renderer_new(0, 0);
    if (!renderer) return;

    hoedown_document *doc = hoedown_document_new(renderer, 0, 1, 0, NULL, NULL);
    if (!doc) {
        free(renderer);
        return;
    }

    hoedown_buffer ob;
    ob.data = malloc(Size);
    if (!ob.data) {
        hoedown_document_free(doc);
        free(renderer);
        return;
    }
    ob.size = 0;
    ob.asize = Size;
    ob.unit = 64;
    ob.data_realloc = realloc;
    ob.data_free = free;
    ob.buffer_free = free;

    hoedown_document_render_inline(doc, &ob, Data, Size);

    free(ob.data);
    hoedown_document_free(doc);
    free(renderer);
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    fuzz_hoedown_document_render(Data, Size);
    fuzz_hoedown_document_new(Data, Size);
    fuzz_hoedown_html_toc_renderer_new(Data, Size);
    fuzz_hoedown_document_render_inline(Data, Size);
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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    