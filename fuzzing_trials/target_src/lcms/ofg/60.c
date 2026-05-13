#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract parameters
    if (size < sizeof(cmsUInt32Number) * 2 + sizeof(cmsFloat64Number) * 4) {
        return 0;
    }

    // Initialize variables for each parameter
    cmsUInt32Number colorSpace = *(const cmsUInt32Number *)data;
    cmsFloat64Number L = *(const cmsFloat64Number *)(data + sizeof(cmsUInt32Number));
    cmsFloat64Number a = *(const cmsFloat64Number *)(data + sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number));
    cmsFloat64Number b = *(const cmsFloat64Number *)(data + sizeof(cmsUInt32Number) + 2 * sizeof(cmsFloat64Number));
    cmsFloat64Number c = *(const cmsFloat64Number *)(data + sizeof(cmsUInt32Number) + 3 * sizeof(cmsFloat64Number));
    cmsUInt32Number intent = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number) + 4 * sizeof(cmsFloat64Number));
    cmsUInt32Number flags = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number) + 4 * sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number));

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateBCHSWabstractProfile(colorSpace, L, a, b, c, intent, flags);

    // Clean up if necessary
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

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

    LLVMFuzzerTestOneInput_60(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
