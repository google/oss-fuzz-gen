#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract a cmsInt32Number
    if (size < sizeof(cmsInt32Number)) {
        return 0;
    }

    // Extract a cmsInt32Number from the data
    cmsInt32Number index = *((cmsInt32Number*)data);

    // Create a dummy cmsToneCurve object
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2);
    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    const cmsCurveSegment* segment = cmsGetToneCurveSegment(index, toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);

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

    LLVMFuzzerTestOneInput_68(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
