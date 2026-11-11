#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_234(const uint8_t *data, size_t size) {
    // Define and initialize variables for the function parameters
    cmsUInt16Number encodedLab[3]; // Array to hold the encoded Lab values
    cmsCIELab lab;

    // Ensure the size is sufficient to extract at least three float values for L, a, b
    if (size < sizeof(float) * 3) {
        return 0;
    }

    // Extract L, a, b values from the input data
    const float *floatData = (const float *)data;
    lab.L = floatData[0];
    lab.a = floatData[1];
    lab.b = floatData[2];

    // Call the function-under-test
    cmsFloat2LabEncoded(encodedLab, &lab);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_234(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
