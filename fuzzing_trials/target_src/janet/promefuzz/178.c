// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_pointer_buffer_unsafe at buffer.c:62:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_formatbv at janet.c:29303:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_formatb at janet.c:29462:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "janet.h"

static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_pointer_buffer_unsafe(const uint8_t *data, size_t size) {
    if (size < sizeof(void *) + 2 * sizeof(int32_t)) {
        return;
    }
    void *memory = (void *)data;
    int32_t capacity = *((int32_t *)(data + sizeof(void *)));
    int32_t count = *((int32_t *)(data + sizeof(void *) + sizeof(int32_t)));

    JanetBuffer *buffer = janet_pointer_buffer_unsafe(memory, capacity, count);
    if (buffer) {
        janet_buffer_deinit(buffer);
    }
}

static void fuzz_janet_buffer(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t)) {
        return;
    }
    int32_t capacity = *((int32_t *)data);

    JanetBuffer *buffer = janet_buffer(capacity);
    if (buffer) {
        janet_buffer_deinit(buffer);
    }
}

static void dummy_va_list_function(JanetBuffer *bufp, const char *format, ...) {
    va_list args;
    va_start(args, format);
    janet_formatbv(bufp, format, args);
    va_end(args);
}

static void fuzz_janet_formatbv(const uint8_t *data, size_t size) {
    if (size < sizeof(JanetBuffer) + 1) {
        return;
    }
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10);

    const char *format = (const char *)(data + sizeof(JanetBuffer));

    dummy_va_list_function(&buffer, format);

    janet_buffer_deinit(&buffer);
}

static void fuzz_janet_formatb(const uint8_t *data, size_t size) {
    if (size < sizeof(JanetBuffer) + 1) {
        return;
    }
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10);

    const char *format = (const char *)(data + sizeof(JanetBuffer));
    janet_formatb(&buffer, format, 123, 'A', 456);

    janet_buffer_deinit(&buffer);
}

static void fuzz_janet_buffer_init(const uint8_t *data, size_t size) {
    if (size < sizeof(JanetBuffer) + sizeof(int32_t)) {
        return;
    }
    JanetBuffer buffer;
    int32_t capacity = *((int32_t *)(data + sizeof(JanetBuffer)));

    janet_buffer_init(&buffer, capacity);
    janet_buffer_deinit(&buffer);
}

int LLVMFuzzerTestOneInput_178(const uint8_t *Data, size_t Size) {
    initialize_janet();
    fuzz_janet_pointer_buffer_unsafe(Data, Size);
    fuzz_janet_buffer(Data, Size);
    fuzz_janet_formatbv(Data, Size);
    fuzz_janet_formatb(Data, Size);
    fuzz_janet_buffer_init(Data, Size);
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

        LLVMFuzzerTestOneInput_178(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    