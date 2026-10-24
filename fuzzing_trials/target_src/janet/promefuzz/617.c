// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_buffer_push_bytes at buffer.c:144:6 in janet.h
// janet_buffer_push_u8 at buffer.c:156:6 in janet.h
// janet_buffer_setcount at buffer.c:105:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_string at string.c:49:16 in janet.h
// janet_buffer_push_string at buffer.c:151:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static void fuzz_janet_buffer_push_string(JanetBuffer *buffer, const uint8_t *data, size_t size) {
    if (size > 0) {
        JanetString janetString = janet_string(data, size);
        janet_buffer_push_string(buffer, janetString);
    }
}

static void fuzz_janet_buffer_push_bytes(JanetBuffer *buffer, const uint8_t *data, size_t size) {
    if (size > 0) {
        janet_buffer_push_bytes(buffer, data, (int32_t)size);
    }
}

static void fuzz_janet_buffer_push_u8(JanetBuffer *buffer, const uint8_t *data, size_t size) {
    if (size > 0) {
        janet_buffer_push_u8(buffer, data[0]);
    }
}

static void fuzz_janet_buffer_setcount(JanetBuffer *buffer, const uint8_t *data, size_t size) {
    if (size >= sizeof(int32_t)) {
        int32_t count;
        memcpy(&count, data, sizeof(int32_t));
        janet_buffer_setcount(buffer, count);
    }
}

int LLVMFuzzerTestOneInput_617(const uint8_t *Data, size_t Size) {
    // Initialize the Janet VM
    janet_init();

    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10);

    fuzz_janet_buffer_push_string(&buffer, Data, Size);
    fuzz_janet_buffer_push_bytes(&buffer, Data, Size);
    fuzz_janet_buffer_push_u8(&buffer, Data, Size);
    fuzz_janet_buffer_setcount(&buffer, Data, Size);

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

        LLVMFuzzerTestOneInput_617(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    