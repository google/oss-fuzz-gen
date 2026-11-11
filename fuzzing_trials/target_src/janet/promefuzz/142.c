// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_pointer_buffer_unsafe at buffer.c:62:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_formatb at janet.c:29462:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_extra at buffer.c:118:6 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void initialize_dummy_memory(void **memory, int32_t *capacity, int32_t *count) {
    *capacity = rand() % 1000;
    *count = rand() % (*capacity + 1);
    *memory = malloc(*capacity);
    if (*memory) {
        memset(*memory, 0, *capacity);
    }
}

static void cleanup_memory(void *memory) {
    if (memory) {
        free(memory);
    }
}

int LLVMFuzzerTestOneInput_142(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data for basic operations

    // Initialize Janet VM
    janet_init();

    // Initialize dummy memory for janet_pointer_buffer_unsafe
    void *memory;
    int32_t capacity, count;
    initialize_dummy_memory(&memory, &capacity, &count);

    // Fuzz janet_pointer_buffer_unsafe
    JanetBuffer *buffer1 = janet_pointer_buffer_unsafe(memory, capacity, count);
    if (buffer1) {
        janet_buffer_deinit(buffer1);
    }

    // Fuzz janet_buffer
    int32_t buf_capacity = (int32_t)(Data[0] % 1000);
    JanetBuffer *buffer2 = janet_buffer(buf_capacity);
    if (buffer2) {
        janet_buffer_deinit(buffer2);
    }

    // Fuzz janet_buffer_init
    JanetBuffer buffer3;
    janet_buffer_init(&buffer3, buf_capacity);
    janet_buffer_deinit(&buffer3);

    // Prepare a dummy buffer for janet_formatb
    JanetBuffer *buffer4 = janet_buffer(128);
    if (buffer4) {
        const char *format = "Formatted number: %d";
        janet_formatb(buffer4, format, (int)(Data[1]));
        janet_buffer_deinit(buffer4);
    }

    // Fuzz janet_buffer_extra
    if (buffer2) {
        int32_t extra_size = (int32_t)(Data[2] % 500);
        janet_buffer_extra(buffer2, extra_size);
        janet_buffer_deinit(buffer2);
    }

    cleanup_memory(memory);

    // Deinitialize Janet VM
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

        LLVMFuzzerTestOneInput_142(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    