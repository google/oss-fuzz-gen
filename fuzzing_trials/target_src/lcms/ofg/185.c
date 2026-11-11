#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_185(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;

    // Check if the size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a temporary memory block to simulate profile data
    void *profileData = malloc(size);
    if (profileData == NULL) {
        return 0;
    }

    // Copy the input data to the profile data
    memcpy(profileData, data, size);

    // Open the profile from memory
    hProfile = cmsOpenProfileFromMem(profileData, size);
    if (hProfile != NULL) {
        // Call the function-under-test
        cmsFloat64Number result = cmsDetectTAC(hProfile);

        // Close the profile
        cmsCloseProfile(hProfile);
    }

    // Free the allocated memory
    free(profileData);

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

    LLVMFuzzerTestOneInput_185(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
