#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_475(const uint8_t *data, size_t size) {
    // Declare and initialize the variables for the function call
    cmsColorSpaceSignature colorSpaceSignature;
    cmsFloat64Number inkLimit;

    // Ensure that the size is sufficient to extract the required data
    if (size < sizeof(cmsColorSpaceSignature) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Extract the cmsColorSpaceSignature from the input data
    colorSpaceSignature = *(cmsColorSpaceSignature *)data;

    // Extract the cmsFloat64Number for inkLimit from the input data
    inkLimit = *(cmsFloat64Number *)(data + sizeof(cmsColorSpaceSignature));

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateInkLimitingDeviceLink(colorSpaceSignature, inkLimit);

    // Clean up the profile if it was successfully created
    if (profile != NULL) {
        cmsCloseProfile(profile);
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

    LLVMFuzzerTestOneInput_475(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
