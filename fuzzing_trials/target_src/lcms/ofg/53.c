#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    void *mem = NULL;
    cmsUInt32Number memSize = 0;
    cmsBool result;

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Allocate memory for the profile data
    mem = malloc(size);
    if (mem == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Set the initial size to the size of the input data
    memSize = (cmsUInt32Number)size;

    // Call the function under test
    result = cmsSaveProfileToMem(hProfile, mem, &memSize);

    // Clean up
    free(mem);
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

    LLVMFuzzerTestOneInput_53(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
