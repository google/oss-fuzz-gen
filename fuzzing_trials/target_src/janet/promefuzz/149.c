// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_string at string.c:49:16 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_buffer at buffer.c:82:14 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_buffer_push_string at buffer.c:151:6 in janet.h
// janet_buffer_push_bytes at buffer.c:144:6 in janet.h
// janet_buffer_push_u8 at buffer.c:156:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
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

static JanetString create_janet_string(const uint8_t *data, size_t size) {
    return janet_string(data, size);
}

int LLVMFuzzerTestOneInput_149(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize the Janet VM
    janet_init();

    // Create a JanetBuffer with a random capacity
    int32_t capacity = (int32_t)(Data[0] % 256);
    JanetBuffer *buffer = janet_buffer(capacity);
    if (!buffer) {
        janet_deinit();
        return 0;
    }

    // Push a string to the buffer
    JanetString jstr = create_janet_string(Data, Size);
    janet_buffer_push_string(buffer, jstr);

    // Push bytes to the buffer
    int32_t len = (int32_t)(Size / 2);
    janet_buffer_push_bytes(buffer, Data, len);

    // Push a single byte to the buffer
    uint8_t byte = Data[Size - 1];
    janet_buffer_push_u8(buffer, byte);

    // Initialize a new buffer and deinitialize it
    JanetBuffer anotherBuffer;
    janet_buffer_init(&anotherBuffer, capacity);
    janet_buffer_deinit(&anotherBuffer);

    // Cleanup
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

        LLVMFuzzerTestOneInput_149(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    