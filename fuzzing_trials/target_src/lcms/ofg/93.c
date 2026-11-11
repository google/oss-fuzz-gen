#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

typedef cmsBool (*cmsSAMPLER16)(const cmsUInt16Number In[], cmsUInt16Number Out[], void * Cargo);

cmsBool sampleFunction_93(const cmsUInt16Number In[], cmsUInt16Number Out[], void * Cargo) {
    // A simple sampler function that copies input to output
    for (int i = 0; i < 3; i++) {
        Out[i] = In[i];
    }
    return TRUE;
}

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) {
        return 0; // Not enough data to extract a valid cmsUInt32Number
    }

    cmsUInt32Number nInputs = *(const cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    if (size < nInputs * sizeof(cmsUInt32Number)) {
        return 0; // Not enough data for the input array
    }

    const cmsUInt32Number *inputArray = (const cmsUInt32Number *)data;

    // Dummy cargo pointer
    void *cargo = (void *)0x1;

    // Call the function-under-test
    cmsBool result = cmsSliceSpace16(nInputs, inputArray, sampleFunction_93, cargo);

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

    LLVMFuzzerTestOneInput_93(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
