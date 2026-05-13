#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Initialize Janet
    janet_init();

    // Create a JanetStream and JanetBuffer
    JanetStream *stream = janet_stream(NULL, 0, 0);
    JanetBuffer *buffer = janet_buffer(10);

    // Ensure the data size is sufficient for int32_t and int
    if (size < sizeof(int32_t) + sizeof(int)) {
        janet_deinit();
        return 0;
    }

    // Extract an int32_t and an int from the data
    int32_t arg1 = *(int32_t *)data;
    int arg2 = *(int *)(data + sizeof(int32_t));

    // Call the function-under-test
    janet_ev_recvchunk(stream, buffer, arg1, arg2);

    // Clean up
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

    LLVMFuzzerTestOneInput_83(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
