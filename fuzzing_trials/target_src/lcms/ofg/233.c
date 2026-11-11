#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_233(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for cmsCIELab
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize variables
    cmsUInt16Number labEncoded[3];
    cmsCIELab lab;

    // Copy data into cmsCIELab structure
    // Assuming data is large enough to fill a cmsCIELab structure
    memcpy(&lab, data, sizeof(cmsCIELab));

    // Call the function-under-test
    cmsFloat2LabEncoded(labEncoded, &lab);

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

    LLVMFuzzerTestOneInput_233(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
