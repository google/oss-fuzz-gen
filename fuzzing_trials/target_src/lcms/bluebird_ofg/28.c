#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE profile;
    cmsUInt32Number intent;
    cmsBool lcmsBoolValue;

    // Ensure the size is sufficient to extract values
    if (size < sizeof(cmsUInt32Number) + sizeof(cmsBool)) {
        return 0;
    }

    // Create a profile from memory using the provided data
    profile = cmsOpenProfileFromMem(data, size);
    if (profile == NULL) {
        return 0;
    }

    // Extract cmsUInt32Number and cmsBool values from data
    intent = *(cmsUInt32Number *)(data + (size - sizeof(cmsUInt32Number) - sizeof(cmsBool)));
    lcmsBoolValue = *(cmsBool *)(data + (size - sizeof(cmsBool)));

    // Call the function-under-test
    cmsUInt32Number result = cmsFormatterForColorspaceOfProfile(profile, intent, lcmsBoolValue);

    // Close the profile
    cmsCloseProfile(profile);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
