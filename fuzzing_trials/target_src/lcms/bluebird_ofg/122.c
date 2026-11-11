#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    cmsUInt8Number profileID[16] = {0};

    // Ensure that the cmsHPROFILE is valid before calling the function
    if (hProfile != NULL) {
        // Call the function-under-test
        cmsSetHeaderProfileID(hProfile, profileID);

        // Close the profile after use
        cmsCloseProfile(hProfile);
    }

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

    LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
