#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_499(const uint8_t *data, size_t size) {
    // Ensure there is enough data to be used as input
    if (size < sizeof(cmsContext)) {
        return 0;
    }

    // Declare and initialize variables for the function parameters
    cmsContext context = (cmsContext)data; // Use data as a pointer for context
    cmsUInt32Number dwFlags = 0; // Initialize to zero, can be varied
    cmsFloat64Number L = 50.0; // Midpoint value for L
    cmsFloat64Number c = 25.0; // Midpoint value for c
    cmsFloat64Number h = 180.0; // Midpoint value for h
    cmsFloat64Number s = 50.0; // Midpoint value for s
    cmsUInt32Number dwType = 1; // Arbitrary non-zero value
    cmsUInt32Number dwIlluminant = 1; // Arbitrary non-zero value

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateBCHSWabstractProfileTHR(context, dwFlags, L, c, h, s, dwType, dwIlluminant);

    // If a profile was created, release it
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

    LLVMFuzzerTestOneInput_499(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
