#include <stdint.h>
#include <stddef.h>
#include "janet.h" // Assuming this is the header file where JanetFiber is defined

int LLVMFuzzerTestOneInput_281(const uint8_t *data, size_t size) {
    // Check if size is sufficient to initialize a JanetFiber
    if (size < sizeof(JanetFiber)) {
        return 0;
    }

    // Initialize a JanetFiber from the input data
    JanetFiber *fiber = (JanetFiber *)data;

    // Call the function-under-test
    janet_async_in_flight(fiber);

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

    LLVMFuzzerTestOneInput_281(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
