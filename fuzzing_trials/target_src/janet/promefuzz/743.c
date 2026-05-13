// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_setcount at buffer.c:105:6 in janet.h
// janet_formatbv at janet.c:29303:6 in janet.h
// janet_buffer_push_cstring at buffer.c:138:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void fuzz_janet_buffer(int32_t capacity) {
    JanetBuffer *buffer = janet_buffer(capacity);
    if (buffer) {
        janet_buffer_deinit(buffer);
    }
}

static void fuzz_janet_buffer_init(int32_t capacity) {
    JanetBuffer buffer;
    janet_buffer_init(&buffer, capacity);
    janet_buffer_deinit(&buffer);
}

static void fuzz_janet_buffer_setcount(JanetBuffer *buffer, int32_t count) {
    if (buffer) {
        janet_buffer_setcount(buffer, count);
    }
}

static void fuzz_janet_formatbv(JanetBuffer *buffer, const char *format, ...) {
    if (buffer && format) {
        va_list args;
        va_start(args, format);
        janet_formatbv(buffer, format, args);
        va_end(args);
    }
}

static void fuzz_janet_buffer_push_cstring(JanetBuffer *buffer, const char *cstring) {
    if (buffer && cstring) {
        janet_buffer_push_cstring(buffer, cstring);
    }
}

int LLVMFuzzerTestOneInput_743(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) {
        return 0;
    }

    // Initialize the Janet VM to ensure proper setup before using Janet APIs
    janet_init();

    int32_t capacity = *((int32_t *)Data);
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    fuzz_janet_buffer(capacity);
    fuzz_janet_buffer_init(capacity);

    JanetBuffer buffer;
    janet_buffer_init(&buffer, capacity);

    if (Size >= sizeof(int32_t)) {
        int32_t count = *((int32_t *)Data);
        Data += sizeof(int32_t);
        Size -= sizeof(int32_t);
        fuzz_janet_buffer_setcount(&buffer, count);
    }

    if (Size > 0) {
        char *format = (char *)malloc(Size + 1);
        if (format) {
            memcpy(format, Data, Size);
            format[Size] = '\0';
            fuzz_janet_formatbv(&buffer, format);
            fuzz_janet_buffer_push_cstring(&buffer, format);
            free(format);
        }
    }

    janet_buffer_deinit(&buffer);

    // Cleanup the Janet VM after use
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

        LLVMFuzzerTestOneInput_743(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    