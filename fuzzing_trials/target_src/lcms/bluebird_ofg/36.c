#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include for memcpy
#include "lcms2.h"

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for cmsCIELab structure
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize the cmsCIELab structure from the input data
    cmsCIELab lab;
    const cmsCIELab *labPtr = &lab;
    memcpy(&lab, data, sizeof(cmsCIELab));

    // Initialize the cmsUInt16Number array
    cmsUInt16Number labEncoded[3] = {0};

    // Call the function-under-test
    cmsFloat2LabEncodedV2(labEncoded, labPtr);

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
