#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_370(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nGridPoints = 2; // A small but non-zero number for grid points
    cmsUInt32Number inputChannels = 3; // Commonly used value
    cmsUInt32Number outputChannels = 3; // Commonly used value

    // Ensure the data size is sufficient for the LUT
    if (size < nGridPoints * inputChannels * outputChannels * sizeof(cmsFloat32Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Cast data to cmsFloat32Number array
    const cmsFloat32Number* table = (const cmsFloat32Number*)data;

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocCLutFloat(context, nGridPoints, inputChannels, outputChannels, table);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_370(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
