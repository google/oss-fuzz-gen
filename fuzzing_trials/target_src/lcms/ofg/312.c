#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_312(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for our use case
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Extract a cmsUInt32Number from the data for input channels
    cmsUInt32Number inputChannels = *((cmsUInt32Number *)data);

    // Create a cmsStage object using the Little CMS API
    cmsStage *stage = cmsStageAllocIdentity(NULL, inputChannels);
    if (stage == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number resultChannels = cmsStageInputChannels(stage);

    // Free the allocated cmsStage object
    cmsStageFree(stage);

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

    LLVMFuzzerTestOneInput_312(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
