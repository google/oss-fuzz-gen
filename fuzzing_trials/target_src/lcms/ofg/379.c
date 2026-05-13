#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_379(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsNAMEDCOLORLIST *namedColorList;
    cmsUInt32Number index;
    char name[32];
    char prefix[32];
    char suffix[32];
    cmsUInt16Number PCS[3];
    cmsUInt16Number device[3];

    // Ensure the data size is sufficient for index
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a named color list with a single color for testing
    namedColorList = cmsAllocNamedColorList(NULL, 1, 32, 32, 32);
    if (namedColorList == NULL) {
        return 0;
    }

    // Copy data to index (ensuring it's within bounds)
    memcpy(&index, data, sizeof(cmsUInt32Number));
    index = index % 1; // Ensure index is within the bounds of the list

    // Initialize strings with some default values
    strncpy(name, "ColorName", sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0'; // Ensure null-termination
    strncpy(prefix, "Prefix", sizeof(prefix) - 1);
    prefix[sizeof(prefix) - 1] = '\0'; // Ensure null-termination
    strncpy(suffix, "Suffix", sizeof(suffix) - 1);
    suffix[sizeof(suffix) - 1] = '\0'; // Ensure null-termination

    // Call the function-under-test
    cmsBool result = cmsNamedColorInfo(namedColorList, index, name, prefix, suffix, PCS, device);

    // Free the named color list
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

    LLVMFuzzerTestOneInput_379(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
