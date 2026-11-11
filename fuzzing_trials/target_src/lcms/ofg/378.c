#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_378(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(NULL, 1, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    cmsUInt32Number index = 0; // Index to access the named color
    char name[33] = {0}; // Ensure enough space for the name, plus null terminator
    char prefix[33] = {0}; // Ensure enough space for the prefix, plus null terminator
    char suffix[33] = {0}; // Ensure enough space for the suffix, plus null terminator
    cmsUInt16Number PCS[3] = {0}; // Placeholder for PCS values
    cmsUInt16Number colorant[3] = {0}; // Placeholder for colorant values

    // Ensure the data is large enough to fill the required fields
    if (size >= 96) {
        memcpy(name, data, 32);
        memcpy(prefix, data + 32, 32);
        memcpy(suffix, data + 64, 32);
    }

    // Call the function-under-test
    cmsBool result = cmsNamedColorInfo(namedColorList, index, name, prefix, suffix, PCS, colorant);

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

    LLVMFuzzerTestOneInput_378(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
