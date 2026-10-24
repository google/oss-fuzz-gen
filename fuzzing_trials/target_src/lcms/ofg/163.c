#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_163(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(NULL, 0, 0, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    // Ensure the data size is sufficient for color names and values
    if (size < 64 + 3 * sizeof(cmsUInt16Number)) {
        cmsFreeNamedColorList(namedColorList);
        return 0;
    }

    // Prepare color name and values
    char colorName[64];
    memcpy(colorName, data, 63);
    colorName[63] = '\0';  // Ensure null-termination

    cmsUInt16Number PCS[3];
    cmsUInt16Number Colorant[3];
    memcpy(PCS, data + 64, 3 * sizeof(cmsUInt16Number));
    memcpy(Colorant, data + 64 + 3 * sizeof(cmsUInt16Number), 3 * sizeof(cmsUInt16Number));

    // Call the function-under-test
    cmsBool result = cmsAppendNamedColor(namedColorList, colorName, PCS, Colorant);

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

    LLVMFuzzerTestOneInput_163(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
