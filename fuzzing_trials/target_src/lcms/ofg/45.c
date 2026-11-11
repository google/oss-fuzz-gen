#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    if (size < 6) {
        return 0; // Ensure there's enough data for pcs and colorant arrays
    }

    // Initialize a cmsNAMEDCOLORLIST object
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(NULL, 1, 1, "Prefix", "Suffix");
    if (!namedColorList) {
        return 0;
    }

    // Prepare PCS and Colorant arrays from input data
    cmsUInt16Number pcs[3];
    cmsUInt16Number colorant[3];

    // Copy data into pcs and colorant arrays
    memcpy(pcs, data, sizeof(cmsUInt16Number) * 3);
    memcpy(colorant, data + sizeof(cmsUInt16Number) * 3, sizeof(cmsUInt16Number) * 3);

    // Add a named color to the list
    if (!cmsNamedColorInfo(namedColorList, 0, "ColorName", "Prefix", "Suffix", pcs, colorant)) {
        cmsFreeNamedColorList(namedColorList);
        return 0;
    }

    // Call the function-under-test
    cmsNAMEDCOLORLIST *duplicatedList = cmsDupNamedColorList(namedColorList);

    // Clean up
    cmsFreeNamedColorList(namedColorList);
    if (duplicatedList) {
        cmsFreeNamedColorList(duplicatedList);
    }

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

    LLVMFuzzerTestOneInput_45(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
