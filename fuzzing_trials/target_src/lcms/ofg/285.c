#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_285(const uint8_t *data, size_t size) {
    cmsNAMEDCOLORLIST *namedColorList = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    if (context == NULL) {
        return 0;
    }

    // Create a named color list with some initial values
    namedColorList = cmsAllocNamedColorList(context, 10, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Add some dummy named colors
    cmsNamedColorInfo(namedColorList, 0, "Color1", "Color1", NULL, NULL, NULL);
    cmsNamedColorInfo(namedColorList, 1, "Color2", "Color2", NULL, NULL, NULL);

    // Call the function-under-test
    cmsUInt32Number count = cmsNamedColorCount(namedColorList);

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

    LLVMFuzzerTestOneInput_285(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
