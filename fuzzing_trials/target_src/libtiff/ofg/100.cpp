#include <cstdint>
#include <cstddef>
#include <cstring>  // Include this header for memcpy

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    if (size < sizeof(double)) {
        return 0; // Insufficient data to form a double
    }

    // Copy the input data into a double variable
    double value;
    memcpy(&value, data, sizeof(double));

    // Call the function-under-test
    TIFFSwabDouble(&value);

    // Additional logic to ensure the function is effectively invoked
    // and the fuzz target is not a no-op.
    // For example, use the value after swabbing to affect control flow.
    if (value != 0.0) {
        // Perform some operation with the swabbed value to ensure coverage
        volatile double result = value * 2.0; // Example operation
        (void)result; // Use the result to avoid compiler optimizations
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

    LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
