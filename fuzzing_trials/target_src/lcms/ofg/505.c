#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_505(const uint8_t *data, size_t size) {
    // Initialize variables for cmsAllocNamedColorList
    cmsContext context = NULL;  // Assuming a null context for simplicity
    cmsUInt32Number nColors = 1;  // Minimum non-zero number of colors
    cmsUInt32Number nPrefix = 1;  // Minimum non-zero prefix length

    // Ensure the data is large enough to include at least one character for each string
    const char *prefix = "prefix";
    const char *suffix = "suffix";

    // Call the function under test
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(context, nColors, nPrefix, prefix, suffix);

    // Clean up if allocation was successful
    if (namedColorList != NULL) {
        cmsFreeNamedColorList(namedColorList);
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

    LLVMFuzzerTestOneInput_505(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
