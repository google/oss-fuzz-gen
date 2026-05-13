#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < 2 * sizeof(int) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Create a new cmsHANDLE (e.g., an IT8 object)
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Allocation failed
    }

    // Extract first integer parameter
    int row = (int)*(int*)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract second integer parameter
    int col = (int)*(int*)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract cmsFloat64Number parameter
    cmsFloat64Number value = (cmsFloat64Number)*(double*)data;

    // Validate row and col values
    if (row < 0 || col < 0) {
        cmsIT8Free(handle);
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsIT8SetDataRowColDbl(handle, row, col, value);

    (void)result; // Suppress unused variable warning

    // Free the cmsHANDLE
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
