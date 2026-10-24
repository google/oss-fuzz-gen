#include <sys/stat.h>
#include <stdint.h>
#include "lcms2.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    // Define and initialize the variables needed for cmsStageAllocCLutFloatGranular
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure there is enough data to extract meaningful values
    if (size < sizeof(cmsUInt32Number) * 3 + sizeof(cmsFloat32Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Extract values from the input data
    const cmsUInt32Number *gridPoints = (const cmsUInt32Number *)data;
    cmsUInt32Number inputChannels = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));
    cmsUInt32Number outputChannels = *(const cmsUInt32Number *)(data + 2 * sizeof(cmsUInt32Number));
    const cmsFloat32Number *table = (const cmsFloat32Number *)(data + 3 * sizeof(cmsUInt32Number));

    // Call the function under test
    cmsStage *stage = cmsStageAllocCLutFloatGranular(context, gridPoints, inputChannels, outputChannels, table);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
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

    LLVMFuzzerTestOneInput_136(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
