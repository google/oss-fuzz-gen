#include <cstdint>
#include <cstddef>
#include <cstring> // Include the C string library for memcpy
#include <cstdio>  // Include C standard I/O for debugging output

extern "C" {
    #include <tiffio.h> // Include the TIFF library header

    // Function-under-test declaration
    void TIFFSwabLong8(uint64_t *value);
}

extern "C" int LLVMFuzzerTestOneInput_237(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for a uint64_t
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Initialize a uint64_t variable from the input data
    uint64_t value;
    memcpy(&value, data, sizeof(uint64_t));

    // Store the original value for comparison
    uint64_t original_value = value;

    // Call the function-under-test
    TIFFSwabLong8(&value);

    // Check if the value has been modified, which indicates the function's effect
    if (value != original_value) {
        // Print the original and modified values for debugging purposes
        printf("Original value: %llu, Swabbed value: %llu\n", original_value, value);
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

    LLVMFuzzerTestOneInput_237(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
