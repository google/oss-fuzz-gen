#include <sys/stat.h>
#include <string.h>
#include "tiffio.h"
#include "cstdint"
#include "cstdlib"
#include "cstring" // Include for memcpy

// Ensure the function is wrapped in extern "C" to handle C++ linkage
extern "C" {
    void TIFFSwabArrayOfFloat(float *array, tmsize_t n);
}

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure the size is a multiple of the size of float
    if (size < sizeof(float) || size % sizeof(float) != 0) {
        return 0;
    }

    // Calculate the number of float elements
    tmsize_t numFloats = static_cast<tmsize_t>(size / sizeof(float));

    // Allocate memory for the float array
    float *floatArray = static_cast<float *>(malloc(size));
    if (floatArray == nullptr) {
        return 0;
    }

    // Copy data into the float array
    memcpy(floatArray, data, size);

    // Call the function-under-test
    TIFFSwabArrayOfFloat(floatArray, numFloats);

    // Clean up
    free(floatArray);

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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
