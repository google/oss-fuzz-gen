#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "lcms2.h" // Assuming lcms2.h is the correct header file for cmsNAMEDCOLORLIST

int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    cmsNAMEDCOLORLIST *namedColorList;

    // Initialize the named color list with some dummy values
    namedColorList = cmsAllocNamedColorList(NULL, 1, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    // Add a named color to the list to ensure it's not empty
    cmsAppendNamedColor(namedColorList, "ColorName", (const cmsUInt16Number *)data, (const cmsUInt16Number *)data);

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

    LLVMFuzzerTestOneInput_109(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
