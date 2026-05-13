#include <stdint.h>
#include <stddef.h>
#include <lcms2.h> // Include the Little CMS 2 library

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsUInt16Number encodedXYZ[3];
    cmsCIEXYZ inputXYZ;

    // Ensure the input size is sufficient for cmsCIEXYZ structure
    if (size < sizeof(cmsCIEXYZ)) {
        return 0;
    }

    // Copy the input data into the cmsCIEXYZ structure
    // Assuming data is properly aligned and large enough
    inputXYZ.X = *((cmsFloat64Number *)(data));
    inputXYZ.Y = *((cmsFloat64Number *)(data + sizeof(cmsFloat64Number)));
    inputXYZ.Z = *((cmsFloat64Number *)(data + 2 * sizeof(cmsFloat64Number)));

    // Call the function-under-test
    cmsFloat2XYZEncoded(encodedXYZ, &inputXYZ);

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

    LLVMFuzzerTestOneInput_116(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
