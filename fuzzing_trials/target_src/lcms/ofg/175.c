#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    int row = 0;
    int col = 0;
    cmsFloat64Number value = 0.0;

    // Ensure that size is sufficient to extract row, col, and value
    if (size < sizeof(int) * 2 + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Extract row, col, and value from the input data
    row = *((int*)data);
    col = *((int*)(data + sizeof(int)));
    value = *((cmsFloat64Number*)(data + sizeof(int) * 2));

    // Call the function-under-test
    cmsBool result = cmsIT8SetDataRowColDbl(handle, row, col, value);

    // Clean up
    cmsIT8Free(handle);

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

    LLVMFuzzerTestOneInput_175(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
