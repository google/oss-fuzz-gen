#include <cstdint>
#include <cstddef>
#include <cstring>  // Include this header for memcpy

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_238(const uint8_t *data, size_t size) {
    // Ensure that the data size is at least the size of uint64_t
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Create a uint64_t variable and initialize it using the input data
    uint64_t value;
    // Copy the first 8 bytes from data to value
    memcpy(&value, data, sizeof(uint64_t));

    // Call the function-under-test
    TIFFSwabLong8(&value);

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

    LLVMFuzzerTestOneInput_238(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
