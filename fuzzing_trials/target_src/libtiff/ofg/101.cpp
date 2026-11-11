#include <cstdint>
#include <cstddef>
#include <cstring>  // Include this for memcpy

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to represent a double
    if (size < sizeof(double)) {
        return 0; // Not enough data to form a double, exit early
    }

    // Initialize a double variable from the input data
    double value;
    // Copy bytes from data to the double variable
    memcpy(&value, data, sizeof(double));

    // Call the function-under-test
    TIFFSwabDouble(&value);

    // Attempt to use the value after swabbing to ensure coverage
    // For demonstration, we'll just print it to a dummy variable
    volatile double dummy = value; // Use volatile to prevent optimization

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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
