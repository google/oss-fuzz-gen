#include <stdint.h>
#include <stddef.h>
#include <lcms2.h> // Assuming the Little CMS library provides this header

// Remove the extern "C" linkage specification for C++ as this is C code
int LLVMFuzzerTestOneInput_362(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    int row, col;
    cmsFloat64Number result;

    // Initialize the handle with a non-null value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Exit if handle allocation fails
    }

    // Ensure the size is sufficient to extract row and col
    if (size < sizeof(int) * 2) {
        cmsIT8Free(handle);
        return 0;
    }

    // Extract row and col values from the input data
    row = *((int *)data);
    col = *((int *)(data + sizeof(int)));

    // Call the function under test
    result = cmsIT8GetDataRowColDbl(handle, row, col);

    // Free the handle after use
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

    LLVMFuzzerTestOneInput_362(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
