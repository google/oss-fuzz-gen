#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy function
#include <lcms2.h>

int LLVMFuzzerTestOneInput_394(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsCIEXYZ dest;
    cmsCIExyY src;

    // Ensure that the size is sufficient to fill the src structure
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Copy data into the src structure
    memcpy(&src, data, sizeof(cmsCIExyY));

    // Call the function-under-test
    cmsxyY2XYZ(&dest, &src);

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

    LLVMFuzzerTestOneInput_394(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
