#include <sys/stat.h>
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

int LLVMFuzzerTestOneInput_785(const uint8_t *Data, size_t Size) {
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_785(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
