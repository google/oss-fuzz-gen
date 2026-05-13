// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_description_b at janet.c:28645:6 in janet.h
// janet_formatbv at janet.c:29303:6 in janet.h
// janet_buffer_push_cstring at buffer.c:138:6 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "janet.h"

static void fuzz_janet_unwrap_buffer(Janet x) {
    JanetBuffer *buffer = janet_unwrap_buffer(x);
    if (buffer && buffer->data) {
        janet_buffer_deinit(buffer);
    }
}

static void fuzz_janet_wrap_buffer(JanetBuffer *buffer) {
    Janet wrapped = janet_wrap_buffer(buffer);
    (void)wrapped;
}

static void fuzz_janet_description_b(JanetBuffer *buffer, Janet x) {
    if (buffer && buffer->data) {
        janet_description_b(buffer, x);
    }
}

static void fuzz_janet_formatbv(JanetBuffer *buffer, const char *format, ...) {
    if (buffer && buffer->data) {
        va_list args;
        va_start(args, format);
        janet_formatbv(buffer, format, args);
        va_end(args);
    }
}

static void fuzz_janet_buffer_push_cstring(JanetBuffer *buffer, const char *cstring) {
    if (buffer && buffer->data && cstring) {
        janet_buffer_push_cstring(buffer, cstring);
    }
}

int LLVMFuzzerTestOneInput_734(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetBuffer) + 1) {
        return 0;
    }

    // Prepare dummy JanetBuffer
    JanetBuffer buffer;
    buffer.gc.flags = 0;
    buffer.gc.data.next = NULL;
    buffer.count = 0;
    buffer.capacity = Size;
    buffer.data = (uint8_t *)malloc(Size);
    if (!buffer.data) {
        return 0;
    }
    memcpy(buffer.data, Data, Size);

    // Prepare Janet value
    Janet x;
    x.pointer = &buffer;

    // Fuzz janet_unwrap_buffer
    fuzz_janet_unwrap_buffer(x);

    // Fuzz janet_wrap_buffer
    fuzz_janet_wrap_buffer(&buffer);

    // Fuzz janet_description_b
    fuzz_janet_description_b(&buffer, x);

    // Fuzz janet_formatbv
    fuzz_janet_formatbv(&buffer, "%c %d %i", Data[0], (int)Data[0], (int)Data[0]);

    // Fuzz janet_buffer_push_cstring
    fuzz_janet_buffer_push_cstring(&buffer, "dummy_cstring");

    // Cleanup
    janet_buffer_deinit(&buffer);
    free(buffer.data);

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

        LLVMFuzzerTestOneInput_734(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    