#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    if (size < 64) {
        // Ensure there's enough data to work with
        return 0;
    }

    cmsNAMEDCOLORLIST *namedColorList;

    // Initialize a named color list with some dummy values
    namedColorList = cmsAllocNamedColorList(NULL, 1, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    // Prepare PCS and Colorant values from the input data
    cmsUInt16Number pcs[3];
    cmsUInt16Number colorant[32];
    
    // Extract PCS values from the input data
    pcs[0] = (cmsUInt16Number)((data[0] << 8) | data[1]);
    pcs[1] = (cmsUInt16Number)((data[2] << 8) | data[3]);
    pcs[2] = (cmsUInt16Number)((data[4] << 8) | data[5]);

    // Extract Colorant values from the input data
    for (int i = 0; i < 32; i++) {
        colorant[i] = (cmsUInt16Number)((data[6 + i * 2] << 8) | data[7 + i * 2]);
    }

    // Add a color to the list using the extracted values
    if (!cmsAppendNamedColor(namedColorList, "FuzzColor", pcs, colorant)) {
        cmsFreeNamedColorList(namedColorList);
        return 0;
    }

    // Call the function-under-test
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

    LLVMFuzzerTestOneInput_110(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
