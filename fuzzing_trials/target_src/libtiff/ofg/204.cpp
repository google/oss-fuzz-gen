#include <cstdint>
#include <cstddef>
#include <tiffio.h>

extern "C" {
    void TIFFSwabShort(uint16_t *);
}

extern "C" int LLVMFuzzerTestOneInput_204(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to hold at least one uint16_t
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Iterate over the input data in chunks of two bytes
    for (size_t i = 0; i <= size - sizeof(uint16_t); i += sizeof(uint16_t)) {
        // Create a uint16_t variable from the input data
        uint16_t value;
        value = (data[i] << 8) | data[i + 1];

        // Call the function-under-test
        TIFFSwabShort(&value);

        // To ensure the function is being tested effectively, we can add a check
        // to see if the value has been swabbed correctly.
        uint16_t expected = (data[i + 1] << 8) | data[i];
        if (value != expected) {
            // If the value doesn't match the expected swabbed value, log an error
            // or take some other action to indicate a test failure.
            return 1;  // Non-zero return value to indicate an issue
        }
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

    LLVMFuzzerTestOneInput_204(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
