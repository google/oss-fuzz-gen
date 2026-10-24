#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Initialize a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a profile from the input data
    cmsHPROFILE inputProfile = cmsOpenProfileFromMem(data, size);
    if (inputProfile == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create a dummy output profile
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();
    if (outputProfile == NULL) {
        cmsCloseProfile(inputProfile);
        cmsDeleteContext(context);
        return 0;
    }

    // Create a transform
    cmsHTRANSFORM transform = cmsCreateTransform(inputProfile, TYPE_RGB_8,
                                                 outputProfile, TYPE_RGB_8,
                                                 INTENT_PERCEPTUAL, 0);
    if (transform == NULL) {
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsNAMEDCOLORLIST *namedColorList = cmsGetNamedColorList(transform);

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
