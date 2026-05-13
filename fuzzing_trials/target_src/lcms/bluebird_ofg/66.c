#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHPROFILE hProfile;
    cmsUInt32Number dwFlags;
    cmsBool bInput;

    // Check if the size is sufficient to extract the necessary values
    if (size < sizeof(cmsUInt32Number) + sizeof(cmsBool)) {
        return 0;
    }

    // Create a profile from memory
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0; // Exit if profile creation fails
    }

    // Extract dwFlags and bInput from the data
    dwFlags = *(cmsUInt32Number *)(data);
    bInput = *(cmsBool *)(data + sizeof(cmsUInt32Number));

    // Call the function-under-test
    cmsUInt32Number result = cmsFormatterForPCSOfProfile(hProfile, dwFlags, bInput);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
