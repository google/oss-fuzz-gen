#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_430(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIEXYZ) * 4) {
        return 0; // Not enough data to fill all parameters
    }

    cmsCIEXYZ sourceWhitePoint;
    cmsCIEXYZ destWhitePoint;
    cmsCIEXYZ sourceXYZ;
    cmsCIEXYZ destXYZ;

    // Copy data into cmsCIEXYZ structures
    memcpy(&sourceWhitePoint, data, sizeof(cmsCIEXYZ));
    memcpy(&destWhitePoint, data + sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));
    memcpy(&sourceXYZ, data + 2 * sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));
    memcpy(&destXYZ, data + 3 * sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));

    // Call the function-under-test
    cmsBool result = cmsAdaptToIlluminant(&destXYZ, &sourceWhitePoint, &destWhitePoint, &sourceXYZ);

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

    LLVMFuzzerTestOneInput_430(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
