#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsHPROFILE inputProfile, outputProfile;
    cmsUInt32Number inputFormat, outputFormat, intent, flags;
    cmsHTRANSFORM transform;

    // Initialize context
    context = cmsCreateContext(NULL, NULL);

    // Create dummy profiles for input and output
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();

    // Initialize other parameters with non-zero values
    inputFormat = TYPE_RGB_8; // Example format
    outputFormat = TYPE_RGB_8; // Example format
    intent = INTENT_PERCEPTUAL; // Example intent
    flags = 0; // Example flags

    // Call the function-under-test
    transform = cmsCreateTransformTHR(context, inputProfile, inputFormat, outputProfile, outputFormat, intent, flags);

    // Clean up
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_58(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
