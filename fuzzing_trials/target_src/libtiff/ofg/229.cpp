#include <cstddef>
#include <cstdint>
#include <cstring> // Include for std::memcpy
#include <tiffio.h>
#include <iostream> // Include for output

extern "C" {
    void TIFFSwabFloat(float *);
}

extern "C" int LLVMFuzzerTestOneInput_229(const uint8_t *data, size_t size) {
    // Ensure we have enough data to create a float
    if (size < sizeof(float)) {
        return 0;
    }

    // Copy the first 4 bytes of data into a float
    float value;
    std::memcpy(&value, data, sizeof(float));

    // Store the original value for comparison
    float originalValue = value;

    // Call the function-under-test
    TIFFSwabFloat(&value);

    // Check if the value was actually swabbed
    if (value != originalValue) {
        // Output the original and modified value to ensure the function had an effect
        std::cout << "Original: " << originalValue << ", Swabbed: " << value << std::endl;
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

    LLVMFuzzerTestOneInput_229(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
