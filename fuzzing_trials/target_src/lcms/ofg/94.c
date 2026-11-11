#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

typedef cmsBool (*cmsSAMPLER16)(const cmsUInt16Number In[], cmsUInt16Number Out[], void* Cargo);

cmsBool sampleFunction_94(const cmsUInt16Number In[], cmsUInt16Number Out[], void* Cargo) {
    // Sample implementation for the sampler function
    for (int i = 0; i < 3; i++) {
        Out[i] = In[i];
    }
    return TRUE;
}

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) return 0;

    cmsUInt32Number nInputs = size / sizeof(cmsUInt32Number);
    cmsUInt32Number *inputArray = (cmsUInt32Number *)malloc(nInputs * sizeof(cmsUInt32Number));
    if (inputArray == NULL) return 0;

    for (size_t i = 0; i < nInputs; i++) {
        inputArray[i] = ((cmsUInt32Number *)data)[i];
    }

    void *cargo = (void *)data;  // Using the data as cargo

    cmsSliceSpace16(nInputs, inputArray, sampleFunction_94, cargo);

    free(inputArray);
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

    LLVMFuzzerTestOneInput_94(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
