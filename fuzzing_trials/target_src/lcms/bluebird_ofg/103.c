#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract parameters
    if (size < sizeof(cmsInt32Number) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Extract a cmsInt32Number from the data
    cmsInt32Number type = *((const cmsInt32Number *)data);
    data += sizeof(cmsInt32Number);
    size -= sizeof(cmsInt32Number);

    // Extract cmsFloat64Number parameters from the data
    const cmsFloat64Number *params = (const cmsFloat64Number *)data;

    // Call the function-under-test
    cmsToneCurve *curve = cmsBuildParametricToneCurve(context, type, params);

    // Clean up
    if (curve != NULL) {
        cmsFreeToneCurve(curve);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
