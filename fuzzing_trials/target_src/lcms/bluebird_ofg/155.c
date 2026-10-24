#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_155(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsFloat64Number temp = 0.0;
    cmsCIExyY whitePoint;

    // Ensure the input size is sufficient to populate cmsCIExyY
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Populate whitePoint with data
    const cmsCIExyY* inputWhitePoint = (const cmsCIExyY*)data;
    whitePoint.x = inputWhitePoint->x;
    whitePoint.y = inputWhitePoint->y;
    whitePoint.Y = inputWhitePoint->Y;

    // Call the function-under-test
    cmsBool result = cmsTempFromWhitePoint(&temp, &whitePoint);

    // Use the result to avoid compiler optimizations that might skip the function call
    if (result) {
        // Do something with temp if needed
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_155(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
