#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>
#include <string.h> // Include for snprintf

int LLVMFuzzerTestOneInput_286(const uint8_t *data, size_t size) {
    cmsNAMEDCOLORLIST *namedColorList = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    if (context == NULL) {
        return 0;
    }

    // Create a named color list with a reasonable number of colors
    namedColorList = cmsAllocNamedColorList(context, 10, 32, "prefix", "suffix");
    if (namedColorList == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Add some named colors to the list
    char colorName[32];
    cmsUInt16Number deviceColorant[4];
    cmsCIEXYZ PCS = {0, 0, 0}; // Initialize PCS to zero

    for (int i = 0; i < 10; i++) {
        snprintf(colorName, sizeof(colorName), "Color%d", i);
        deviceColorant[0] = (cmsUInt16Number)(i * 1000);
        deviceColorant[1] = (cmsUInt16Number)(i * 1000);
        deviceColorant[2] = (cmsUInt16Number)(i * 1000);
        deviceColorant[3] = (cmsUInt16Number)(i * 1000);
        cmsAppendNamedColor(namedColorList, colorName, &PCS, deviceColorant);
    }

    // Call the function-under-test
    cmsUInt32Number colorCount = cmsNamedColorCount(namedColorList);

    // Clean up
    cmsFreeNamedColorList(namedColorList);
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_286(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
