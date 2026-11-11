#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_506(const uint8_t *data, size_t size) {
    cmsContext context = NULL; // Assuming a null context for simplicity
    cmsUInt32Number nColors = 5; // Arbitrary non-zero number of colors
    cmsUInt32Number nPrefix = 3; // Arbitrary non-zero prefix length

    // Ensure that the size is large enough to extract two strings
    if (size < 2) return 0;

    // Extract two strings from the input data
    const char *prefix = (const char *)data;
    const char *suffix = (const char *)(data + 1);

    // Ensure the strings are null-terminated
    char prefixBuffer[256];
    char suffixBuffer[256];
    strncpy(prefixBuffer, prefix, sizeof(prefixBuffer) - 1);
    prefixBuffer[sizeof(prefixBuffer) - 1] = '\0';
    strncpy(suffixBuffer, suffix, sizeof(suffixBuffer) - 1);
    suffixBuffer[sizeof(suffixBuffer) - 1] = '\0';

    // Call the function-under-test
    cmsNAMEDCOLORLIST *colorList = cmsAllocNamedColorList(context, nColors, nPrefix, prefixBuffer, suffixBuffer);

    // Clean up
    if (colorList != NULL) {
        cmsFreeNamedColorList(colorList);
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

    LLVMFuzzerTestOneInput_506(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
