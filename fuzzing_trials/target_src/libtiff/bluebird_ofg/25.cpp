#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "cstdlib"
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Ensure we have enough data to form at least one double
    if (size < sizeof(double)) {
        return 0;
    }

    // Calculate the number of doubles we can extract from the input data
    tmsize_t numDoubles = size / sizeof(double);

    // Allocate memory for the doubles
    double *doubleArray = static_cast<double *>(malloc(numDoubles * sizeof(double)));
    if (doubleArray == nullptr) {
        return 0;
    }

    // Copy data into the double array
    for (tmsize_t i = 0; i < numDoubles; ++i) {
        doubleArray[i] = *reinterpret_cast<const double *>(data + i * sizeof(double));
    }

    // Call the function-under-test
    TIFFSwabArrayOfDouble(doubleArray, numDoubles);

    // Clean up
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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
