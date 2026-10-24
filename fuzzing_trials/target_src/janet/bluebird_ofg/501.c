#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include for memcpy
#include "janet.h"

int LLVMFuzzerTestOneInput_501(const uint8_t *data, size_t size) {
    Janet janetValue;
    JanetString description;

    // Initialize the Janet environment
    janet_init();

    // Ensure the input size is at least the size of a Janet value
    if (size >= sizeof(Janet)) {
        // Copy the input data into a Janet value
        memcpy(&janetValue, data, sizeof(Janet));

        // Call the function-under-test
        description = janet_description(janetValue);

        // Use the description in some way, e.g., print or log it
        // Here we just ensure it is not NULL
        if (description != NULL) {
            // Do something with the description, if needed
        }
    }

    // Deinitialize the Janet environment
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

    LLVMFuzzerTestOneInput_501(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
