#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <stdlib.h> // Include stdlib.h for malloc and free

int LLVMFuzzerTestOneInput_413(const uint8_t *data, size_t size) {
    // Define and initialize all necessary variables
    cmsHTRANSFORM transform;
    const void *inputBuffer;
    void *outputBuffer;
    cmsUInt32Number sizeOfBuffer;
    cmsUInt32Number stride;

    // Initialize the transform object
    cmsHPROFILE inputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();
    transform = cmsCreateTransform(inputProfile, TYPE_RGBA_8, outputProfile, TYPE_RGBA_8, INTENT_PERCEPTUAL, 0);

    // Ensure the size is large enough to avoid buffer overflow
    if (size < 4) {
        cmsDeleteTransform(transform);
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    // Assign the input buffer from the data
    inputBuffer = (const void *)data;

    // Allocate memory for the output buffer
    outputBuffer = malloc(size);
    if (outputBuffer == NULL) {
        cmsDeleteTransform(transform);
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    // Set the size of the buffer and the stride
    sizeOfBuffer = (cmsUInt32Number)size;
    stride = 4; // Assuming 4 bytes per pixel for RGBA

    // Call the function-under-test
    cmsDoTransformStride(transform, inputBuffer, outputBuffer, sizeOfBuffer, stride);

    // Clean up
    free(outputBuffer);
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);

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

    LLVMFuzzerTestOneInput_413(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
