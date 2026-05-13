#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIExyY)) {
        return 0; // Not enough data to form a cmsCIExyY structure
    }

    // Initialize a cmsCIExyY structure
    cmsCIExyY ciexyY;
    ciexyY.x = (double)data[0] / 255.0; // Normalize to [0, 1]
    ciexyY.y = (double)data[1] / 255.0; // Normalize to [0, 1]
    ciexyY.Y = (double)data[2] / 255.0; // Normalize to [0, 1]

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLab2Profile(&ciexyY);

    // Clean up
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

    LLVMFuzzerTestOneInput_5(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
