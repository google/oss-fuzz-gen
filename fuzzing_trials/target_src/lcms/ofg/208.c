#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Added for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_208(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsCIExyY whitePoint;

    // Ensure the input data is large enough to populate whitePoint
    if (size < sizeof(cmsCIExyY)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Copy data into whitePoint, ensuring no overflow
    memcpy(&whitePoint, data, sizeof(cmsCIExyY));

    // Call the function under test
    cmsHPROFILE profile = cmsCreateLab4ProfileTHR(context, &whitePoint);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_208(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
