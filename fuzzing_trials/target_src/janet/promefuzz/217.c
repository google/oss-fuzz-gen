// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_pretty at janet.c:29166:14 in janet.h
// janet_formatbv at janet.c:29303:6 in janet.h
// janet_formatb at janet.c:29462:14 in janet.h
// janet_buffer_extra at buffer.c:118:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include "janet.h"

static void fuzz_janet_buffer(int32_t capacity) {
    JanetBuffer *buffer = janet_buffer(capacity);
    if (buffer) {
        janet_buffer_deinit(buffer);
    }
}

static void fuzz_janet_pretty(JanetBuffer *buffer, int depth, int flags, Janet x) {
    janet_pretty(buffer, depth, flags, x);
}

static void fuzz_janet_formatbv(JanetBuffer *buffer, const char *format, ...) {
    va_list args;
    va_start(args, format);
    janet_formatbv(buffer, format, args);
    va_end(args);
}

static void fuzz_janet_formatb(JanetBuffer *buffer, const char *format, ...) {
    va_list args;
    va_start(args, format);
    janet_formatb(buffer, format, args);
    va_end(args);
}

static void fuzz_janet_buffer_extra(JanetBuffer *buffer, int32_t n) {
    janet_buffer_extra(buffer, n);
}

int LLVMFuzzerTestOneInput_217(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return 0;

    // Initialize Janet environment
    janet_init();

    int32_t capacity = *(int32_t *)Data;
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    JanetBuffer *buffer = janet_buffer(capacity);
    if (!buffer) {
        janet_deinit();
        return 0;
    }

    if (Size >= sizeof(int32_t) * 2) {
        int depth = *(int32_t *)Data;
        int flags = *(int32_t *)(Data + sizeof(int32_t));
        Data += sizeof(int32_t) * 2;
        Size -= sizeof(int32_t) * 2;

        Janet x;
        if (Size >= sizeof(Janet)) {
            x = *(Janet *)Data;
            Data += sizeof(Janet);
            Size -= sizeof(Janet);
        } else {
            x = (Janet){0};
        }

        fuzz_janet_pretty(buffer, depth, flags, x);
    }

    if (Size > 0) {
        // Ensure null-termination for the format string
        char *format = (char *)malloc(Size + 1);
        if (format) {
            memcpy(format, Data, Size);
            format[Size] = '\0';
            fuzz_janet_formatbv(buffer, format);
            free(format);
        }
    }

    if (Size > 0) {
        // Ensure null-termination for the format string
        char *format = (char *)malloc(Size + 1);
        if (format) {
            memcpy(format, Data, Size);
            format[Size] = '\0';
            fuzz_janet_formatb(buffer, format);
            free(format);
        }
    }

    if (Size >= sizeof(int32_t)) {
        int32_t extra = *(int32_t *)Data;
        fuzz_janet_buffer_extra(buffer, extra);
    }

    janet_buffer_deinit(buffer);

    // Deinitialize Janet environment
    janet_deinit();

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

        LLVMFuzzerTestOneInput_217(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    