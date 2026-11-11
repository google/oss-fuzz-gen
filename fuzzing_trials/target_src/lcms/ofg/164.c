#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsNAMEDCOLORLIST *namedColorList;
    char colorName[32];
    cmsUInt16Number PCS[3];
    cmsUInt16Number colorant[3];

    // Ensure size is sufficient for the operations
    if (size < 32 + 3 * sizeof(cmsUInt16Number) * 2) {
        return 0;
    }

    // Create a named color list with arbitrary parameters
    namedColorList = cmsAllocNamedColorList(NULL, 1, 3, "prefix", "suffix");
    if (!namedColorList) {
        return 0;
    }

    // Copy data into colorName, ensuring null-termination
    memcpy(colorName, data, 31);
    colorName[31] = '\0';

    // Copy data into PCS and colorant arrays
    memcpy(PCS, data + 32, 3 * sizeof(cmsUInt16Number));
    memcpy(colorant, data + 32 + 3 * sizeof(cmsUInt16Number), 3 * sizeof(cmsUInt16Number));

    // Call the function-under-test
    cmsBool result = cmsAppendNamedColor(namedColorList, colorName, PCS, colorant);

    // Clean up
    cmsFreeNamedColorList(namedColorList);

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

    LLVMFuzzerTestOneInput_164(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
