#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_317(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to populate the structures
    if (size < sizeof(cmsCIEXYZ) * 2 + sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize cmsCIEXYZ and cmsCIELab structures
    cmsCIEXYZ sourceXYZ;
    cmsCIELab destLab;
    cmsCIEXYZ whitePointXYZ;

    // Populate the cmsCIEXYZ structures from the input data
    sourceXYZ.X = *(const double *)(data);
    sourceXYZ.Y = *(const double *)(data + sizeof(double));
    sourceXYZ.Z = *(const double *)(data + 2 * sizeof(double));

    whitePointXYZ.X = *(const double *)(data + 3 * sizeof(double));
    whitePointXYZ.Y = *(const double *)(data + 4 * sizeof(double));
    whitePointXYZ.Z = *(const double *)(data + 5 * sizeof(double));

    // Call the function-under-test
    cmsXYZ2Lab(&whitePointXYZ, &destLab, &sourceXYZ);

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

    LLVMFuzzerTestOneInput_317(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
