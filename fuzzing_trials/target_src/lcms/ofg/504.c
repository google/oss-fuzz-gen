#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_504(const uint8_t *data, size_t size) {
    cmsFloat64Number tempResult;
    cmsCIExyY whitePoint;

    // Ensure the size is sufficient to fill the cmsCIExyY structure
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Initialize the cmsCIExyY structure with data
    whitePoint.x = *(cmsFloat64Number *)(data);
    whitePoint.y = *(cmsFloat64Number *)(data + sizeof(cmsFloat64Number));
    whitePoint.Y = *(cmsFloat64Number *)(data + 2 * sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsTempFromWhitePoint(&tempResult, &whitePoint);

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

    LLVMFuzzerTestOneInput_504(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
