#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

// Define a sample function for cmsSAMPLERFLOAT
static cmsBool SampleFunction(const cmsFloat32Number In[], cmsFloat32Number Out[], void* Cargo) {
    // A simple example that just copies input to output
    for (int i = 0; i < 3; i++) {
        Out[i] = In[i];
    }
    return TRUE;
}

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Extract a cmsUInt32Number from the data
    cmsUInt32Number nInputs = *((const cmsUInt32Number *)data);
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Ensure there's enough data for the cmsUInt32Number array
    if (size < nInputs * sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Allocate and initialize the array of cmsUInt32Numbers
    cmsUInt32Number* coordinates = (cmsUInt32Number*)data;
    data += nInputs * sizeof(cmsUInt32Number);
    size -= nInputs * sizeof(cmsUInt32Number);

    // Create a dummy Cargo
    void* cargo = (void*)data;

    // Call the function-under-test
    cmsSliceSpaceFloat(nInputs, coordinates, SampleFunction, cargo);

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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
