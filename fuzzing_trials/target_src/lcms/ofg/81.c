#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>  // Assuming the function is part of the Little CMS library

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    cmsUInt32Number options;

    // Ensure there is enough data to extract cmsUInt32Number and to create a profile
    if (size < sizeof(cmsUInt32Number)) {
        return 0; // Not enough data to extract cmsUInt32Number
    }

    // Use the first part of data as options
    options = *((cmsUInt32Number*)data);

    // Create a profile handle from the remaining data
    handle = cmsOpenProfileFromMem(data + sizeof(cmsUInt32Number), size - sizeof(cmsUInt32Number));
    if (handle == NULL) {
        return 0; // Failed to create a valid handle
    }

    // Call the function-under-test
    cmsBool result = cmsGDBCompute(handle, options);

    // Use the result in some way to avoid compiler optimizations
    if (result) {
        // Do something if needed
    }

    // Clean up the handle
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

    LLVMFuzzerTestOneInput_81(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
