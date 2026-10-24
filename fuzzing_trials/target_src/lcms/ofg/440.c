#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_440(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsTagSignature) + sizeof(cmsUInt32Number)) {
        return 0; // Not enough data to proceed
    }

    // Extract cmsTagSignature from the input data
    cmsTagSignature tagSig;
    memcpy(&tagSig, data, sizeof(cmsTagSignature));

    // Extract cmsUInt32Number from the input data
    cmsUInt32Number bufferSize;
    memcpy(&bufferSize, data + sizeof(cmsTagSignature), sizeof(cmsUInt32Number));

    // Create a dummy profile for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0; // Failed to create profile
    }

    // Allocate memory for the buffer
    void *buffer = malloc(bufferSize);
    if (buffer == NULL) {
        cmsCloseProfile(hProfile);
        return 0; // Failed to allocate buffer
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsReadRawTag(hProfile, tagSig, buffer, bufferSize);

    // Clean up
    free(buffer);
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

    LLVMFuzzerTestOneInput_440(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
