#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_207(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsCIExyY whitePoint;

    // Ensure the data size is sufficient to populate the whitePoint structure
    if (size < sizeof(cmsCIExyY)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Populate the whitePoint structure with data
    whitePoint.x = *(const double *)(data);
    whitePoint.y = *(const double *)(data + sizeof(double));
    whitePoint.Y = *(const double *)(data + 2 * sizeof(double));

    // Call the function-under-test
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

    LLVMFuzzerTestOneInput_207(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
