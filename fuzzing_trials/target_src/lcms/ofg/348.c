#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include this for memcpy
#include <lcms2.h>   // Ensure this is included for Little CMS functions

int LLVMFuzzerTestOneInput_348(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    cmsUInt32Number tableCount;

    // Ensure the size is sufficient for creating a valid handle
    if (size < sizeof(cmsHANDLE)) {
        return 0;
    }

    // Create a temporary memory block to simulate a handle
    handle = (cmsHANDLE)malloc(sizeof(cmsHANDLE));
    if (handle == NULL) {
        return 0;
    }

    // Simulate copying data into the handle
    memcpy(handle, data, sizeof(cmsHANDLE));

    // Call the function-under-test
    tableCount = cmsIT8TableCount(handle);

    // Clean up
    free(handle);

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

    LLVMFuzzerTestOneInput_348(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
