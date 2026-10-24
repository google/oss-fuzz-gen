#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_509(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a double value
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize the parameters
    cmsCIExyY whitePoint;
    cmsFloat64Number temp;

    // Copy data into temp, ensuring no buffer overflow
    memcpy(&temp, data, sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsBool result = cmsWhitePointFromTemp(&whitePoint, temp);

    // Use the result to avoid any compiler optimizations
    if (result) {
        // Do something with whitePoint if necessary
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

    LLVMFuzzerTestOneInput_509(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
