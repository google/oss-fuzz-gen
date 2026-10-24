// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_setcount at buffer.c:105:6 in janet.h
// janet_formatbv at janet.c:29303:6 in janet.h
// janet_buffer_push_cstring at buffer.c:138:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "janet.h"

static void fuzz_janet_buffer(int32_t capacity) {
    JanetBuffer *buffer = janet_buffer(capacity);
    if (buffer) {
        janet_buffer_deinit(buffer);
    }
}

static void fuzz_janet_buffer_init(JanetBuffer *buffer, int32_t capacity) {
    JanetBuffer *initialized_buffer = janet_buffer_init(buffer, capacity);
    if (initialized_buffer) {
        janet_buffer_deinit(initialized_buffer);
    }
}

static void fuzz_janet_buffer_setcount(JanetBuffer *buffer, int32_t count) {
    if (buffer) {
        janet_buffer_setcount(buffer, count);
    }
}

static void fuzz_janet_formatbv(JanetBuffer *buffer, const char *format, ...) {
    if (!buffer || !format) return;

    va_list args;
    va_start(args, format);
    janet_formatbv(buffer, format, args);
    va_end(args);
}

static void fuzz_janet_buffer_push_cstring(JanetBuffer *buffer, const char *cstring) {
    if (buffer && cstring) {
        janet_buffer_push_cstring(buffer, cstring);
    }
}

int LLVMFuzzerTestOneInput_759(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // ensure we have enough data for at least one int32_t

    // Initialize the Janet VM
    janet_init();

    int32_t capacity = *((int32_t *)Data);
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    // Fuzz janet_buffer
    fuzz_janet_buffer(capacity);

    // Prepare a dummy JanetBuffer
    JanetBuffer buffer;
    fuzz_janet_buffer_init(&buffer, capacity);

    // Fuzz janet_buffer_setcount
    if (Size >= sizeof(int32_t)) {
        int32_t count = *((int32_t *)Data);
        fuzz_janet_buffer_setcount(&buffer, count);
        Data += sizeof(int32_t);
        Size -= sizeof(int32_t);
    }

    // Fuzz janet_formatbv
    if (Size > 1) { // Ensure there's at least one character and a null terminator
        size_t format_len = strnlen((const char *)Data, Size - 1);
        if (format_len < Size - 1) { // Ensure null termination within bounds
            const char *format = (const char *)Data;
            fuzz_janet_formatbv(&buffer, format);
        }
    }

    // Fuzz janet_buffer_push_cstring
    if (Size > 1) { // Ensure there's at least one character and a null terminator
        size_t cstring_len = strnlen((const char *)Data, Size - 1);
        if (cstring_len < Size - 1) { // Ensure null termination within bounds
            const char *cstring = (const char *)Data;
            fuzz_janet_buffer_push_cstring(&buffer, cstring);
        }
    }

    // Clean up
    janet_buffer_deinit(&buffer);

    // Deinitialize the Janet VM
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

        LLVMFuzzerTestOneInput_759(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    