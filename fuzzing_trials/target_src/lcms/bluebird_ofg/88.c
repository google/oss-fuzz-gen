#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    cmsContext context = (cmsContext)data; // Cast data to cmsContext for fuzzing
    cmsHPROFILE inputProfile = NULL;
    cmsHPROFILE outputProfile = NULL;
    cmsUInt32Number inputFormat = 0;
    cmsUInt32Number outputFormat = 0;
    cmsUInt32Number intent = 0;
    cmsUInt32Number flags = 0;

    // Ensure there is enough data to create at least two profiles
    if (size < 128) {
        return 0; // Not enough data to proceed
    }

    // Create input and output profiles from data
    inputProfile = cmsOpenProfileFromMem(data, size / 2);
    outputProfile = cmsOpenProfileFromMem(data + size / 2, size / 2);

    // Check if profiles were created successfully
    if (inputProfile == NULL || outputProfile == NULL) {
        if (inputProfile != NULL) {
            cmsCloseProfile(inputProfile);
        }
        if (outputProfile != NULL) {
            cmsCloseProfile(outputProfile);
        }
        return 0;
    }

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateTransformTHR(
        context,
        inputProfile,
        inputFormat,
        outputProfile,
        outputFormat,
        intent,
        flags
    );

    // Clean up
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);

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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
