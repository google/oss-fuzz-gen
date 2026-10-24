#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    cmsStage *stage = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure the data size is sufficient to create a cmsStage
    if (size >= sizeof(cmsFloat32Number)) {
        // Allocate a stage using the lcms2 API
        stage = cmsStageAllocIdentity(context, 3); // Assuming 3 channels for RGB

        if (stage != NULL) {
            // Assuming data is used to manipulate the stage in some meaningful way
            // Here we just demonstrate a simple usage of the stage
            cmsStageSampleCLut16bit(stage, (uint16_t *)data, size / sizeof(uint16_t), 0);

            // Call the function-under-test
            cmsStageFree(stage);

            // Set stage to NULL after freeing to avoid double-free
            stage = NULL;
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

    LLVMFuzzerTestOneInput_28(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
