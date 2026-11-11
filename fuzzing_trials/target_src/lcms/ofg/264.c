#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_264(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize variables
    cmsHTRANSFORM transform;
    cmsUInt32Number numPixels = *(const cmsUInt32Number *)data;
    const void *inputBuffer = (const void *)(data + sizeof(cmsUInt32Number));
    void *outputBuffer = malloc(size - sizeof(cmsUInt32Number));

    // Check if memory allocation was successful
    if (outputBuffer == NULL) {
        return 0;
    }

    // Create a dummy transform for testing purposes
    cmsHPROFILE hInProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE hOutProfile = cmsCreate_sRGBProfile();
    transform = cmsCreateTransform(hInProfile, TYPE_RGB_8, hOutProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);

    // Call the function-under-test
    cmsDoTransform(transform, inputBuffer, outputBuffer, numPixels);

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(hInProfile);
    cmsCloseProfile(hOutProfile);
    free(outputBuffer);

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

    LLVMFuzzerTestOneInput_264(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
