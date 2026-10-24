#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a memory-based profile for fuzzing
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract cmsUInt32Number from data
    cmsUInt32Number manufacturer = *(const cmsUInt32Number *)data;

    // Call the function-under-test
    cmsSetHeaderManufacturer(hProfile, manufacturer);

    // Close the profile
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

    LLVMFuzzerTestOneInput_123(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
