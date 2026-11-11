// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_put_utf8 at buffer.c:276:6 in buffer.h
// hoedown_buffer_cstr at buffer.c:224:1 in buffer.h
// hoedown_buffer_putf at buffer.c:150:1 in buffer.h
// hoedown_document_render at document.c:4070:1 in document.h
// hoedown_buffer_new at buffer.c:73:1 in buffer.h
// hoedown_document_new at document.c:3979:1 in document.h
// hoedown_document_free at document.c:4246:1 in document.h
// hoedown_buffer_uninit at buffer.c:66:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "buffer.h"
#include "document.h"

static void fuzz_hoedown_buffer_put_utf8(hoedown_buffer *buf, const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(unsigned int)) {
        unsigned int codepoint = *((unsigned int *)Data);
        hoedown_buffer_put_utf8(buf, codepoint);
    }
}

static void fuzz_hoedown_buffer_cstr(hoedown_buffer *buf) {
    const char *cstr = hoedown_buffer_cstr(buf);
    (void)cstr; // Use the result to avoid unused variable warning
}

static void fuzz_hoedown_buffer_putf(hoedown_buffer *buf, const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb+");
    if (file) {
        fwrite(Data, 1, Size, file);
        rewind(file);
        hoedown_buffer_putf(buf, file);
        fclose(file);
    }
}

static void fuzz_hoedown_document_render(hoedown_document *doc, hoedown_buffer *ob, const uint8_t *Data, size_t Size) {
    hoedown_document_render(doc, ob, Data, Size);
}

int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize a hoedown_buffer
    hoedown_buffer *buf = hoedown_buffer_new(64);
    if (!buf) return 0;

    // Fuzz hoedown_buffer_put_utf8
    fuzz_hoedown_buffer_put_utf8(buf, Data, Size);

    // Fuzz hoedown_buffer_cstr
    fuzz_hoedown_buffer_cstr(buf);

    // Fuzz hoedown_buffer_putf
    fuzz_hoedown_buffer_putf(buf, Data, Size);

    // Initialize a hoedown_document
    hoedown_renderer renderer = {0};
    hoedown_document *doc = hoedown_document_new(&renderer, HOEDOWN_EXT_AUTOLINK, 16, 0, NULL, NULL);
    if (doc) {
        // Fuzz hoedown_document_render
        fuzz_hoedown_document_render(doc, buf, Data, Size);
        hoedown_document_free(doc);
    }

    // Clean up
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

        LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    