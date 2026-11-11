#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include the string.h library for memcpy
#include "lcms2.h"

int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to create a profile
    if (size < sizeof(cmsCIExyYTRIPLE)) {
        return 0;
    }

    // Create a cmsCIExyYTRIPLE structure from the input data
    cmsCIExyYTRIPLE triple;
    memcpy(&triple, data, sizeof(cmsCIExyYTRIPLE));

    // Create a profile using the input data
    cmsHPROFILE profile = cmsCreateXYZProfile();
    if (profile == NULL) {
        return 0;
    }

    // Set the header attributes using the fuzzing input
    cmsSetHeaderAttributes(profile, *(cmsUInt32Number *)data);

    // Access the profile to ensure it is used
    cmsCIExyY *whitePoint = (cmsCIExyY *)cmsReadTag(profile, cmsSigMediaWhitePointTag);
    if (whitePoint != NULL) {
        volatile double x = whitePoint->x;
        volatile double y = whitePoint->y;
        volatile double Y = whitePoint->Y;
        (void)x;
        (void)y;
        (void)Y;
    }

    // Close the profile
    cmsCloseProfile(profile);

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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
