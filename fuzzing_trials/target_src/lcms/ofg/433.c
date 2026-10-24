#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_433(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsTagSignature tagSignature;
    void *result;

    // Ensure the input size is large enough to extract a cmsTagSignature
    if (size < sizeof(cmsTagSignature)) {
        return 0;
    }

    // Create a profile from the data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a cmsTagSignature from the data
    tagSignature = *(cmsTagSignature *)data;

    // Call the function-under-test
    result = cmsReadTag(hProfile, tagSignature);

    // Clean up
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

    LLVMFuzzerTestOneInput_433(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
