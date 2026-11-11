#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the test
    if (size < sizeof(cmsColorSpaceSignature) + sizeof(cmsToneCurve*)) {
        return 0;
    }

    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    
    // Extract cmsColorSpaceSignature from data
    cmsColorSpaceSignature colorSpaceSignature;
    memcpy(&colorSpaceSignature, data, sizeof(cmsColorSpaceSignature));

    // Allocate and initialize cmsToneCurve pointers
    const cmsToneCurve *toneCurves[3];
    for (int i = 0; i < 3; i++) {
        toneCurves[i] = cmsBuildGamma(context, 2.2); // Example gamma value
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLinearizationDeviceLinkTHR(context, colorSpaceSignature, toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    for (int i = 0; i < 3; i++) {
        if (toneCurves[i] != NULL) {
            cmsFreeToneCurve(toneCurves[i]);
        }
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

    LLVMFuzzerTestOneInput_3(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
