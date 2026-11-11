#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>  // For memcpy
#include "lcms2.h"

// The function signature for the fuzzer entry point
int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract all parameters
    if (size < sizeof(cmsCIELab) + 4 * sizeof(double)) {
        return 0;
    }

    // Initialize and assign values to cmsCIELab and doubles
    cmsCIELab lab;
    double d1, d2, d3, d4;

    // Copy data into cmsCIELab structure
    memcpy(&lab, data, sizeof(cmsCIELab));
    data += sizeof(cmsCIELab);

    // Extract doubles from the remaining data
    memcpy(&d1, data, sizeof(double));
    data += sizeof(double);
    memcpy(&d2, data, sizeof(double));
    data += sizeof(double);
    memcpy(&d3, data, sizeof(double));
    data += sizeof(double);
    memcpy(&d4, data, sizeof(double));

    // Call the function-under-test
    cmsBool result = cmsDesaturateLab(&lab, d1, d2, d3, d4);

    // Use the result to avoid compiler optimizations
    (void)result;

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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
