#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_225(const uint8_t *data, size_t size) {
    // Initialize variables for cmsCreateInkLimitingDeviceLinkTHR
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsColorSpaceSignature colorSpaceSignature;
    cmsFloat64Number limit;

    // Ensure size is sufficient to extract required data
    if (size < sizeof(cmsColorSpaceSignature) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Extract cmsColorSpaceSignature from data
    colorSpaceSignature = *(cmsColorSpaceSignature *)data;

    // Extract cmsFloat64Number from data
    limit = *(cmsFloat64Number *)(data + sizeof(cmsColorSpaceSignature));

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateInkLimitingDeviceLinkTHR(context, colorSpaceSignature, limit);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
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

    LLVMFuzzerTestOneInput_225(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
