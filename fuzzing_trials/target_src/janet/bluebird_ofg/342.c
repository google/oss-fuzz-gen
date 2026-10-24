#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"
#include <string.h> // Include for memcpy

int LLVMFuzzerTestOneInput_342(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract necessary parameters
    if (size < sizeof(JanetFiber) + sizeof(Janet) + sizeof(JanetSignal)) {
        return 0;
    }

    // Initialize Janet environment
    janet_init();

    // Create a buffer to copy the input data
    uint8_t *buffer = (uint8_t *)malloc(size);
    if (!buffer) {
        janet_deinit();
        return 0;
    }
    memcpy(buffer, data, size);

    // Extract parameters from the copied buffer
    JanetFiber *fiber = (JanetFiber *)buffer;
    Janet janet_value;
    JanetSignal signal;

    // Ensure the extracted pointers are within bounds
    if (size >= sizeof(JanetFiber)) {
        fiber = (JanetFiber *)(buffer);
    }
    if (size >= sizeof(JanetFiber) + sizeof(Janet)) {
        janet_value = *(Janet *)(buffer + sizeof(JanetFiber));
    }
    if (size >= sizeof(JanetFiber) + sizeof(Janet) + sizeof(JanetSignal)) {
        signal = *(JanetSignal *)(buffer + sizeof(JanetFiber) + sizeof(Janet));
    }

    // Call the function-under-test
    janet_schedule_signal(fiber, janet_value, signal);

    // Free the allocated buffer
    free(buffer);

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_342(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
