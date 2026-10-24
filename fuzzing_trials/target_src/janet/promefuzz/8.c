// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_pointer_buffer_unsafe at buffer.c:62:14 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_ensure at buffer.c:88:6 in janet.h
// janet_buffer_setcount at buffer.c:105:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_extra at buffer.c:118:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void initialize_janet() {
    static int janet_initialized = 0;
    if (!janet_initialized) {
        janet_init();
        janet_initialized = 1;
    }
}

static void fuzz_janet_pointer_buffer_unsafe(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *) + 2 * sizeof(int32_t)) return;

    void *memory = *(void **)Data;
    Data += sizeof(void *);
    int32_t capacity = *(int32_t *)Data;
    Data += sizeof(int32_t);
    int32_t count = *(int32_t *)Data;

    // Call the target function
    JanetBuffer *buffer = janet_pointer_buffer_unsafe(memory, capacity, count);

    // Clean-up if necessary
    if (buffer && buffer->data) {
        free(buffer->data);
    }
}

static void fuzz_janet_buffer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t capacity = *(int32_t *)Data;

    // Call the target function
    JanetBuffer *buffer = janet_buffer(capacity);

    // Clean-up is handled by Janet's garbage collector
}

static void fuzz_janet_buffer_ensure(JanetBuffer *buffer, const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(int32_t)) return;

    int32_t capacity = *(int32_t *)Data;
    Data += sizeof(int32_t);
    int32_t growth = *(int32_t *)Data;

    // Call the target function
    janet_buffer_ensure(buffer, capacity, growth);
}

static void fuzz_janet_buffer_setcount(JanetBuffer *buffer, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t count = *(int32_t *)Data;

    // Call the target function
    janet_buffer_setcount(buffer, count);
}

static void fuzz_janet_buffer_init(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t capacity = *(int32_t *)Data;

    JanetBuffer buffer;

    // Call the target function
    janet_buffer_init(&buffer, capacity);

    // Clean-up if necessary
    if (buffer.data) {
        free(buffer.data);
    }
}

static void fuzz_janet_buffer_extra(JanetBuffer *buffer, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;

    int32_t n = *(int32_t *)Data;

    // Call the target function
    janet_buffer_extra(buffer, n);
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    // Initialize Janet runtime
    initialize_janet();

    // Fuzz janet_pointer_buffer_unsafe
    fuzz_janet_pointer_buffer_unsafe(Data, Size);

    // Fuzz janet_buffer
    fuzz_janet_buffer(Data, Size);

    // Prepare a JanetBuffer for the following functions
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 0);

    // Fuzz janet_buffer_ensure
    fuzz_janet_buffer_ensure(&buffer, Data, Size);

    // Fuzz janet_buffer_setcount
    fuzz_janet_buffer_setcount(&buffer, Data, Size);

    // Fuzz janet_buffer_init
    fuzz_janet_buffer_init(Data, Size);

    // Fuzz janet_buffer_extra
    fuzz_janet_buffer_extra(&buffer, Data, Size);

    // Clean-up if necessary
    if (buffer.data) {
        free(buffer.data);
    }

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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    