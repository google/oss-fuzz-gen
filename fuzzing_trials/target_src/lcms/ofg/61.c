#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt32Number) * 3 + sizeof(cmsFloat64Number) * 4) {
        return 0;
    }

    cmsUInt32Number intent = *(cmsUInt32Number *)(data);
    cmsFloat64Number bp = *(cmsFloat64Number *)(data + sizeof(cmsUInt32Number));
    cmsFloat64Number wp = *(cmsFloat64Number *)(data + sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number));
    cmsFloat64Number lstar = *(cmsFloat64Number *)(data + sizeof(cmsUInt32Number) + 2 * sizeof(cmsFloat64Number));
    cmsFloat64Number chroma = *(cmsFloat64Number *)(data + sizeof(cmsUInt32Number) + 3 * sizeof(cmsFloat64Number));
    cmsUInt32Number flags = *(cmsUInt32Number *)(data + sizeof(cmsUInt32Number) + 4 * sizeof(cmsFloat64Number));
    cmsUInt32Number profileFlags = *(cmsUInt32Number *)(data + sizeof(cmsUInt32Number) + 4 * sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number));

    cmsHPROFILE profile = cmsCreateBCHSWabstractProfile(intent, bp, wp, lstar, chroma, flags, profileFlags);

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

    LLVMFuzzerTestOneInput_61(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
