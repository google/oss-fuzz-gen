#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <stdlib.h> // Include for malloc and free

int LLVMFuzzerTestOneInput_263(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to perform the operation
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize the Little CMS context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a simple transform for fuzzing
    cmsHPROFILE inputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();
    cmsHTRANSFORM transform = cmsCreateTransform(inputProfile, TYPE_RGB_8, outputProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);

    // Ensure the transform was created successfully
    if (transform == NULL) {
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        cmsDeleteContext(context);
        return 0;
    }

    // Prepare input and output buffers
    const void *inputBuffer = (const void *)data;
    void *outputBuffer = malloc(size);

    // Ensure the output buffer was allocated successfully
    if (outputBuffer == NULL) {
        cmsDeleteTransform(transform);
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        cmsDeleteContext(context);
        return 0;
    }

    // Use the first few bytes of data to determine the number of pixels
    cmsUInt32Number numPixels = size / sizeof(uint8_t);

    // Call the function-under-test
    cmsDoTransform(transform, inputBuffer, outputBuffer, numPixels);

    // Clean up
    free(outputBuffer);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_263(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
