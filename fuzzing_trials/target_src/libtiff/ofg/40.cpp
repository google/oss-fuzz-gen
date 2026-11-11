#include <cstdint>
#include <cstdlib>
#include <cstring>  // Include for memcpy
#include <tiffio.h>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Ensure that the size is a multiple of the size of double
    if (size < sizeof(double) || size % sizeof(double) != 0) {
        return 0;
    }

    // Calculate the number of double elements
    tmsize_t numDoubles = size / sizeof(double);

    // Allocate memory for the double array
    double *doubleArray = static_cast<double *>(malloc(size));
    if (doubleArray == nullptr) {
        return 0;
    }

    // Copy the data into the double array
    memcpy(doubleArray, data, size);

    // Check if the array is non-zero to ensure meaningful input
    bool nonZero = false;
    for (tmsize_t i = 0; i < numDoubles; ++i) {
        if (doubleArray[i] != 0.0) {
            nonZero = true;
            break;
        }
    }

    if (nonZero) {
        // Call the function under test with non-zero data
        TIFFSwabArrayOfDouble(doubleArray, numDoubles);
    }

    // Free the allocated memory
    free(doubleArray);

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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
