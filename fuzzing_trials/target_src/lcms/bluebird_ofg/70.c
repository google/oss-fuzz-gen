#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for processing
    if (size < 3) {
        return 0; // Not enough data to proceed
    }

    // Initialize variables
    cmsHTRANSFORM transform = NULL;
    cmsHPROFILE inputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();
    if (inputProfile == NULL || outputProfile == NULL) {
        if (inputProfile) cmsCloseProfile(inputProfile);
        if (outputProfile) cmsCloseProfile(outputProfile);
        return 0; // Exit if profile creation fails
    }

    // Create a transform for testing
    transform = cmsCreateTransform(inputProfile, TYPE_RGB_8, outputProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    if (transform == NULL) {
        return 0; // Exit if transform creation fails
    }

    const void *inputBuffer = data; // Use the provided data as input
    void *outputBuffer = malloc(size); // Allocate memory for output buffer
    if (outputBuffer == NULL) {
        cmsDeleteTransform(transform);
        return 0; // Exit if memory allocation fails
    }

    // Define some arbitrary non-zero values for stride and other parameters
    cmsUInt32Number sizeOfElement = 1;
    cmsUInt32Number strideIn = 1;
    cmsUInt32Number strideOut = 1;
    cmsUInt32Number bytesPerLineIn = (cmsUInt32Number)size;
    cmsUInt32Number bytesPerLineOut = (cmsUInt32Number)size;

    // Call the function-under-test
    cmsDoTransformLineStride(transform, inputBuffer, outputBuffer, sizeOfElement, strideIn, strideOut, bytesPerLineIn, bytesPerLineOut, size);

    // Free the allocated memory for output buffer
    free(outputBuffer);

    // Delete the transform
    cmsDeleteTransform(transform);

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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
