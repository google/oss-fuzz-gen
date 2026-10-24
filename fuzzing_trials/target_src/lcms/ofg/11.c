#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    cmsHTRANSFORM transform = NULL;
    cmsHPROFILE inputProfile = NULL;
    cmsHPROFILE outputProfile = NULL;
    cmsUInt32Number inputFormat = TYPE_RGB_8;
    cmsUInt32Number outputFormat = TYPE_RGB_8;
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;
    cmsUInt32Number outputFormatResult;

    // Create dummy profiles for input and output
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();

    if (inputProfile != NULL && outputProfile != NULL) {
        // Create a transform
        transform = cmsCreateTransform(inputProfile, inputFormat, outputProfile, outputFormat, intent, flags);

        if (transform != NULL) {
            // Ensure we have enough data to process
            if (size >= 3) {
                // Use the input data to create a source buffer
                uint8_t *src = (uint8_t *)data;
                uint8_t dst[3]; // Destination buffer for transformed data

                // Call the function-under-test
                cmsDoTransform(transform, src, dst, 1);

                // Optionally, use the outputFormatResult to verify or log the result
                outputFormatResult = cmsGetTransformOutputFormat(transform);
            }

            // Clean up transform
            cmsDeleteTransform(transform);
        }

        // Clean up profiles
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
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

    LLVMFuzzerTestOneInput_11(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
