#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include this for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_240(const uint8_t *data, size_t size) {
    // Ensure that the data is large enough to fill the cmsCIExyY structure
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Initialize a cmsCIExyY structure with the input data
    cmsCIExyY ciexyY;
    memcpy(&ciexyY, data, sizeof(cmsCIExyY));

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLab4Profile(&ciexyY);

    // Clean up if a valid profile was created
    if (profile != NULL) {
        cmsCloseProfile(profile);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_240(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
