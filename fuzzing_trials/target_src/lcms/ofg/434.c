#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>  // Ensure that the Little CMS library is available

// Function to initialize a dummy profile for testing
cmsHPROFILE createDummyProfile() {
    // Create a dummy profile using Little CMS functions
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    return hProfile;
}

int LLVMFuzzerTestOneInput_434(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract a cmsTagSignature
    if (size < sizeof(cmsTagSignature)) {
        return 0;
    }

    // Initialize a dummy profile
    cmsHPROFILE hProfile = createDummyProfile();

    // Extract a cmsTagSignature from the input data
    cmsTagSignature tagSignature = *(const cmsTagSignature *)data;

    // Call the function-under-test
    void *result = cmsReadTag(hProfile, tagSignature);

    // Clean up the profile
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

    LLVMFuzzerTestOneInput_434(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
