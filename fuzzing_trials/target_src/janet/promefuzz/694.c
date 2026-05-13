// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_buffer_push_u32 at buffer.c:171:6 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_formatb at janet.c:29462:14 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_init at vm.c:1652:5 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "janet.h"

static void fuzz_janet_buffer_push_u32(JanetBuffer *buffer, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;
    uint32_t x;
    memcpy(&x, Data, sizeof(uint32_t));
    janet_buffer_push_u32(buffer, x);
}

static void fuzz_janet_buffer(JanetBuffer **buffer, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t capacity;
    memcpy(&capacity, Data, sizeof(int32_t));
    *buffer = janet_buffer(capacity);
}

static void fuzz_janet_buffer_deinit(JanetBuffer *buffer) {
    if (buffer) {
        janet_buffer_deinit(buffer);
    }
}

static void fuzz_janet_formatb(JanetBuffer *buffer, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    char *format = (char *)malloc(Size + 1);
    if (!format) return;
    memcpy(format, Data, Size);
    format[Size] = '\0';
    janet_formatb(buffer, format);
    free(format);
}

static void fuzz_janet_buffer_init(JanetBuffer *buffer, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t capacity;
    memcpy(&capacity, Data, sizeof(int32_t));
    janet_buffer_init(buffer, capacity);
}

int LLVMFuzzerTestOneInput_694(const uint8_t *Data, size_t Size) {
    static int janet_initialized = 0;
    if (!janet_initialized) {
        janet_init();
        janet_initialized = 1;
    }

    JanetBuffer *buffer = NULL;

    // Fuzz janet_buffer
    fuzz_janet_buffer(&buffer, Data, Size);

    // Fuzz janet_buffer_push_u32
    if (buffer) {
        fuzz_janet_buffer_push_u32(buffer, Data, Size);
    }

    // Fuzz janet_formatb
    if (buffer) {
        fuzz_janet_formatb(buffer, Data, Size);
    }

    // Fuzz janet_buffer_init
    if (buffer) {
        fuzz_janet_buffer_init(buffer, Data, Size);
    }

    // Clean up
    fuzz_janet_buffer_deinit(buffer);

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

        LLVMFuzzerTestOneInput_694(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    