#include <stdint.h>
#include <stddef.h>
#include <lcms2.h> // Include the Little CMS library header

// Define the LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read a cmsColorSpaceSignature
    if (size < sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    // Interpret the input data as a cmsColorSpaceSignature
    cmsColorSpaceSignature colorSpaceSignature = *(const cmsColorSpaceSignature *)data;

    // Call the function-under-test
    cmsUInt32Number channels = cmsChannelsOf(colorSpaceSignature);

    // Use the result to avoid compiler optimizations that might skip the call
    (void)channels;

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

    LLVMFuzzerTestOneInput_154(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
