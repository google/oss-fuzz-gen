#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include string.h for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_217(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to populate cmsCIELab structure
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    cmsUInt16Number output[3]; // Array to store the encoded Lab values
    cmsCIELab inputLab;

    // Copy data into cmsCIELab structure
    // Assuming data is properly aligned and large enough
    memcpy(&inputLab, data, sizeof(cmsCIELab));

    // Call the function-under-test
    cmsFloat2LabEncodedV2(output, &inputLab);

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

    LLVMFuzzerTestOneInput_217(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
