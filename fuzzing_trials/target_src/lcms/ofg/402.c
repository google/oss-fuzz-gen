#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_402(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Create a dummy named color list
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(NULL, 1, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    // Add a dummy named color to the list
    const char *colorName = "DummyColor";
    cmsCIEXYZ dummyXYZ = { 0.0, 0.0, 0.0 };
    cmsAppendNamedColor(namedColorList, colorName, &dummyXYZ, &dummyXYZ);

    // Ensure the input data is null-terminated
    char *inputColorName = (char *)malloc(size + 1);
    if (inputColorName == NULL) {
        cmsFreeNamedColorList(namedColorList);
        return 0;
    }
    memcpy(inputColorName, data, size);
    inputColorName[size] = '\0';

    // Call the function-under-test
    cmsInt32Number index = cmsNamedColorIndex(namedColorList, inputColorName);

    // Clean up
    free(inputColorName);
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

    LLVMFuzzerTestOneInput_402(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
