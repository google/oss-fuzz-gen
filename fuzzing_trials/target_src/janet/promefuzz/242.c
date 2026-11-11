// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_ensure at buffer.c:88:6 in janet.h
// janet_buffer_push_u16 at buffer.c:163:6 in janet.h
// janet_formatb at janet.c:29462:14 in janet.h
// janet_buffer_extra at buffer.c:118:6 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void init_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_buffer(int32_t capacity) {
    JanetBuffer *buffer = janet_buffer(capacity);
    if (buffer) {
        janet_buffer_deinit(buffer);
    }
}

static void fuzz_janet_buffer_ensure(JanetBuffer *buffer, int32_t capacity, int32_t growth) {
    if (buffer) {
        janet_buffer_ensure(buffer, capacity, growth);
    }
}

static void fuzz_janet_buffer_push_u16(JanetBuffer *buffer, uint16_t x) {
    if (buffer) {
        janet_buffer_push_u16(buffer, x);
    }
}

static void fuzz_janet_formatb(JanetBuffer *buffer, const char *format) {
    if (buffer && format) {
        janet_formatb(buffer, format);
    }
}

static void fuzz_janet_buffer_extra(JanetBuffer *buffer, int32_t n) {
    if (buffer) {
        janet_buffer_extra(buffer, n);
    }
}

int LLVMFuzzerTestOneInput_242(const uint8_t *Data, size_t Size) {
    init_janet();

    if (Size < 4) return 0;

    int32_t capacity = *(const int32_t *)Data;
    Data += 4;
    Size -= 4;

    JanetBuffer *buffer = janet_buffer(capacity);
    if (!buffer) return 0;

    if (Size >= 8) {
        int32_t ensure_capacity = *(const int32_t *)Data;
        int32_t growth = *(const int32_t *)(Data + 4);
        fuzz_janet_buffer_ensure(buffer, ensure_capacity, growth);
        Data += 8;
        Size -= 8;
    }

    if (Size >= 2) {
        uint16_t x = *(const uint16_t *)Data;
        fuzz_janet_buffer_push_u16(buffer, x);
        Data += 2;
        Size -= 2;
    }

    if (Size > 0) {
        char *format = (char *)malloc(Size + 1);
        if (format) {
            memcpy(format, Data, Size);
            format[Size] = '\0';
            fuzz_janet_formatb(buffer, format);
            free(format);
        }
    }

    if (Size >= 4) {
        int32_t extra_n = *(const int32_t *)Data;
        fuzz_janet_buffer_extra(buffer, extra_n);
    }

    janet_buffer_deinit(buffer);
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

        LLVMFuzzerTestOneInput_242(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    