// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_buffer_push_u32 at buffer.c:171:6 in janet.h
// janet_pointer_buffer_unsafe at buffer.c:62:14 in janet.h
// janet_formatb at janet.c:29462:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void write_to_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_762(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) + sizeof(int32_t) * 3) {
        return 0; // Not enough data for meaningful fuzzing
    }

    // Initialize the Janet VM
    janet_init();

    // Initialize a JanetBuffer
    int32_t initial_capacity = *(int32_t *)Data;
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    JanetBuffer *buffer = janet_buffer(initial_capacity);
    if (!buffer) {
        janet_deinit();
        return 0;
    }

    // Push a u32 value into the buffer
    uint32_t u32_value = *(uint32_t *)Data;
    Data += sizeof(uint32_t);
    Size -= sizeof(uint32_t);

    janet_buffer_push_u32(buffer, u32_value);

    // Create a JanetBuffer from a memory block
    int32_t capacity = *(int32_t *)Data;
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    int32_t count = *(int32_t *)Data;
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    if (capacity >= 0 && count >= 0 && count <= capacity) {
        void *memory = malloc(capacity);
        if (memory) {
            JanetBuffer *unsafe_buffer = janet_pointer_buffer_unsafe(memory, capacity, count);
            if (unsafe_buffer) {
                // Use the unsafe_buffer
            }
            free(memory);
        }
    }

    // Format a string into the buffer
    if (Size > 0) {
        char *format_string = (char *)malloc(Size + 1);
        if (format_string) {
            memcpy(format_string, Data, Size);
            format_string[Size] = '\0';
            janet_formatb(buffer, format_string);
            free(format_string);
        }
    }

    // Deinitialize the buffer
    janet_buffer_deinit(buffer);

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

        LLVMFuzzerTestOneInput_762(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    