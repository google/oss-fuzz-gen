#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include for memcpy
#include <lcms2.h>   // Include for Little CMS functions and types

int LLVMFuzzerTestOneInput_395(const uint8_t *data, size_t size) {
    // Check if the input data is large enough to fill a cmsCIExyY structure
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Initialize the cmsCIExyY structure from the input data
    cmsCIExyY input_xyY;
    memcpy(&input_xyY, data, sizeof(cmsCIExyY));

    // Initialize the cmsCIEXYZ structure
    cmsCIEXYZ output_XYZ;

    // Call the function-under-test
    cmsxyY2XYZ(&output_XYZ, &input_xyY);

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

    LLVMFuzzerTestOneInput_395(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
