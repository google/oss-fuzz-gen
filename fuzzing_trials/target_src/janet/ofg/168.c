#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Ensure you have the Janet library headers included for JanetChannel and related functions.

int LLVMFuzzerTestOneInput_168(const uint8_t *data, size_t size) {
    // Initialize the Janet runtime environment if necessary
    janet_init();

    // Define and initialize the parameter for janet_channel_make
    uint32_t capacity = 0;

    // Ensure the size is at least 4 bytes to read a uint32_t
    if (size >= sizeof(uint32_t)) {
        // Copy the first 4 bytes from data into capacity
        capacity = *((uint32_t *)data);
    }

    // Call the function-under-test
    JanetChannel *channel = janet_channel_make(capacity);

    // Clean up the Janet runtime environment if necessary
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

    LLVMFuzzerTestOneInput_168(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
