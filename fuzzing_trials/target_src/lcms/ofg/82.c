#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    cmsHPROFILE handle;
    cmsUInt32Number options;

    // Ensure we have enough data for a cmsUInt32Number and some profile data
    if (size < sizeof(cmsUInt32Number) + 4) { // Assuming at least 4 bytes for profile data
        return 0;
    }

    // Initialize handle with a valid value
    handle = cmsOpenProfileFromMem(data + sizeof(cmsUInt32Number), size - sizeof(cmsUInt32Number));
    if (handle == NULL) {
        return 0;
    }

    // Extract options from the input data
    options = *(const cmsUInt32Number *)(data);

    // Validate the options if possible (depends on the expected range of options)
    // For example, if options should be within a certain range, add checks here

    // Call the function-under-test
    cmsBool result = cmsGDBCompute(handle, options);

    // Clean up
    cmsCloseProfile(handle);

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

    LLVMFuzzerTestOneInput_82(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
