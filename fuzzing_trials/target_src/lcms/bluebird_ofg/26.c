#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h" // Include the Little CMS library header

// Remove 'extern "C"' as it is not compatible with C language
int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract the required values
    if (size < 6 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize two cmsCIELab structures
    cmsCIELab lab1;
    cmsCIELab lab2;

    // Extract cmsFloat64Number values from the input data
    cmsFloat64Number L1 = ((cmsFloat64Number *)data)[0];
    cmsFloat64Number a1 = ((cmsFloat64Number *)data)[1];
    cmsFloat64Number b1 = ((cmsFloat64Number *)data)[2];
    cmsFloat64Number L2 = ((cmsFloat64Number *)data)[3];
    cmsFloat64Number a2 = ((cmsFloat64Number *)data)[4];
    cmsFloat64Number b2 = ((cmsFloat64Number *)data)[5];

    // Assign values to the cmsCIELab structures
    lab1.L = L1;
    lab1.a = a1;
    lab1.b = b1;
    lab2.L = L2;
    lab2.a = a2;
    lab2.b = b2;

    // Extract the kL, kC, and kH values from the remaining data
    cmsFloat64Number kL = 1.0; // Use default value 1.0
    cmsFloat64Number kC = 1.0; // Use default value 1.0
    cmsFloat64Number kH = 1.0; // Use default value 1.0

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsCIE2000DeltaE(&lab1, &lab2, kL, kC, kH);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
