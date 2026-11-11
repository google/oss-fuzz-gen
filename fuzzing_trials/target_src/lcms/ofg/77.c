#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    cmsHTRANSFORM transform;
    cmsNAMEDCOLORLIST *namedColorList;

    // Ensure size is sufficient for a transform
    if (size < sizeof(cmsHTRANSFORM)) {
        return 0;
    }

    // Initialize the transform with some dummy data
    // Note: This is a placeholder. In a real scenario, you would use actual color profiles.
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    transform = cmsCreateTransform(hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    if (transform == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call the function-under-test
    namedColorList = cmsGetNamedColorList(transform);

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(hProfile);

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

    LLVMFuzzerTestOneInput_77(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
