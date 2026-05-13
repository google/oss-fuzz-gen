#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
    #include "tiffio.h"  // Assuming TIFFSwabLong is declared here
}

extern "C" int LLVMFuzzerTestOneInput_243(const uint8_t *data, size_t size) {
    // Ensure the size is at least 4 bytes to accommodate a uint32_t
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Copy the first 4 bytes from the input data to a uint32_t variable
    uint32_t original_value;
    memcpy(&original_value, data, sizeof(uint32_t));

    // Make a copy of the original value to compare after swabbing
    uint32_t value = original_value;

    // Call the function-under-test
    TIFFSwabLong(&value);

    // To ensure the function is effectively tested, we can use the value after swabbing
    volatile uint32_t used_value = value; // Use volatile to prevent optimization out
    (void)used_value; // Suppress unused variable warning

    // Additional operations to ensure the function is effectively tested
    // Check if the swabbed value is different from the original
    if (used_value != original_value) {
        // Perform some operation to ensure the value is used
        // This could be a logging operation or a simple assignment
        volatile uint32_t check = used_value + 1; // Use volatile to prevent optimization out
        (void)check; // Suppress unused variable warning
    } else {
        // If the value hasn't changed, we can still perform an operation to ensure coverage
        volatile uint32_t unchanged_check = used_value - 1; // Use volatile to prevent optimization out
        (void)unchanged_check; // Suppress unused variable warning
    }

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

    LLVMFuzzerTestOneInput_243(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
