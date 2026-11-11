// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_put_utf8 at buffer.c:276:6 in buffer.h
// hoedown_buffer_cstr at buffer.c:224:1 in buffer.h
// hoedown_buffer_putf at buffer.c:150:1 in buffer.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_buffer_uninit at buffer.c:66:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "document.h"
#include "buffer.h"

static void fuzz_hoedown_buffer_put_utf8(hoedown_buffer *buf, const uint8_t *data, size_t size) {
    if (size < 4) return;
    unsigned int codepoint = *(unsigned int *)data;
    hoedown_buffer_put_utf8(buf, codepoint);
}

static void fuzz_hoedown_buffer_cstr(hoedown_buffer *buf) {
    const char *cstr = hoedown_buffer_cstr(buf);
    (void)cstr; // Use cstr to avoid unused variable warning
}

static void fuzz_hoedown_buffer_putf(hoedown_buffer *buf, const uint8_t *data, size_t size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return;
    fwrite(data, 1, size, file);
    fseek(file, 0, SEEK_SET);
    hoedown_buffer_putf(buf, file);
    fclose(file);
}

static void fuzz_hoedown_document_render(hoedown_document *doc, hoedown_buffer *ob, const uint8_t *data, size_t size) {
    hoedown_document_render(doc, ob, data, size);
}

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    size_t unit_size = 64;
    hoedown_buffer *buf = hoedown_buffer_new(unit_size);
    if (!buf) return 0;

    // Fuzz hoedown_buffer_put_utf8
    fuzz_hoedown_buffer_put_utf8(buf, Data, Size);

    // Fuzz hoedown_buffer_cstr
    fuzz_hoedown_buffer_cstr(buf);

    // Fuzz hoedown_buffer_putf
    fuzz_hoedown_buffer_putf(buf, Data, Size);

    // Initialize a dummy document for rendering
    hoedown_document *doc = NULL; // Assuming a function to create or initialize the document
    hoedown_buffer ob;
    ob.data = NULL;
    ob.size = 0;
    ob.asize = 0;
    ob.unit = unit_size;

    // Fuzz hoedown_document_render
    if (doc) {
        fuzz_hoedown_document_render(doc, &ob, Data, Size);
    }

    // Cleanup
    hoedown_buffer_uninit(buf);

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

        LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    