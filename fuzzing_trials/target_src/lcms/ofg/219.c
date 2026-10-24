#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_219(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a memory-based profile to avoid using a real file
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a cmsUInt32Number from the input data
    cmsUInt32Number flags = *(cmsUInt32Number*)data;

    // Call the function-under-test with the profile and flags
    cmsSetHeaderFlags(hProfile, flags);

    // Close the profile after use
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

    LLVMFuzzerTestOneInput_219(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
