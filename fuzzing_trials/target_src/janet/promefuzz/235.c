// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_pointer_buffer_unsafe at buffer.c:62:14 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_ensure at buffer.c:88:6 in janet.h
// janet_buffer_setcount at buffer.c:105:6 in janet.h
// janet_optbuffer at janet.c:4538:1 in janet.h
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
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void fuzz_janet_pointer_buffer_unsafe(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *) + 2 * sizeof(int32_t)) return;
    void *memory = (void *)(Data);
    int32_t capacity = *(int32_t *)(Data + sizeof(void *));
    int32_t count = *(int32_t *)(Data + sizeof(void *) + sizeof(int32_t));
    if (count >= 0 && count <= capacity) {
        janet_pointer_buffer_unsafe(memory, capacity, count);
    }
}

static void fuzz_janet_buffer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t capacity = *(int32_t *)Data;
    janet_buffer(capacity);
}

static void fuzz_janet_buffer_ensure(JanetBuffer *buffer, const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(int32_t)) return;
    int32_t capacity = *(int32_t *)Data;
    int32_t growth = *(int32_t *)(Data + sizeof(int32_t));
    if (growth > 0) {
        janet_buffer_ensure(buffer, capacity, growth);
    }
}

static void fuzz_janet_buffer_setcount(JanetBuffer *buffer, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t count = *(int32_t *)Data;
    janet_buffer_setcount(buffer, count);
}

static void fuzz_janet_optbuffer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + 3 * sizeof(int32_t)) return;
    const Janet *argv = (const Janet *)Data;
    int32_t argc = *(int32_t *)(Data + sizeof(Janet));
    int32_t n = *(int32_t *)(Data + sizeof(Janet) + sizeof(int32_t));
    int32_t dflt_len = *(int32_t *)(Data + sizeof(Janet) + 2 * sizeof(int32_t));
    janet_optbuffer(argv, argc, n, dflt_len);
}

static void fuzz_janet_buffer_extra(JanetBuffer *buffer, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t n = *(int32_t *)Data;
    janet_buffer_extra(buffer, n);
}

int LLVMFuzzerTestOneInput_235(const uint8_t *Data, size_t Size) {
    janet_init(); // Initialize the Janet environment
    JanetBuffer *buffer = janet_buffer(10); // Initialize a buffer with a default capacity
    fuzz_janet_pointer_buffer_unsafe(Data, Size);
    fuzz_janet_buffer(Data, Size);
    fuzz_janet_buffer_ensure(buffer, Data, Size);
    fuzz_janet_buffer_setcount(buffer, Data, Size);
    fuzz_janet_optbuffer(Data, Size);
    fuzz_janet_buffer_extra(buffer, Data, Size);
    janet_deinit(); // Clean up the Janet environment
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

        LLVMFuzzerTestOneInput_235(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    