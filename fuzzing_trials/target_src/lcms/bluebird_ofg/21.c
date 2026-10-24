#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

// Define a sample function for cmsSAMPLERFLOAT
cmsBool sampleFunction(const cmsFloat32Number In[], cmsFloat32Number Out[], void* Cargo) {
    // A simple example function that copies input to output
    for (int i = 0; i < 3; i++) {
        Out[i] = In[i];
    }
    return TRUE;
}

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    cmsStage *stage;
    void *cargo = NULL;
    cmsUInt32Number flags = 0;

    // Initialize LCMS stage
    stage = cmsStageAllocCLutFloat(NULL, 3, 3, 3, NULL);
    if (stage == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsStageSampleCLutFloat(stage, sampleFunction, cargo, flags);

    // Free resources
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
