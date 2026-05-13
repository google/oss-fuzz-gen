#include <cstdint>
#include <cstdlib>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    if (size < sizeof(float)) {
        return 0; // Not enough data to form even one float
    }

    // Calculate the number of floats we can extract from the input data
    tmsize_t numFloats = size / sizeof(float);

    // Allocate memory for the float array
    float *floatArray = static_cast<float*>(malloc(numFloats * sizeof(float)));
    if (floatArray == nullptr) {
        return 0; // Memory allocation failed
    }

    // Copy data into the float array
    for (tmsize_t i = 0; i < numFloats; ++i) {
        floatArray[i] = reinterpret_cast<const float*>(data)[i];
    }

    // Call the function-under-test
    TIFFSwabArrayOfFloat(floatArray, numFloats);

    // Free the allocated memory
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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
