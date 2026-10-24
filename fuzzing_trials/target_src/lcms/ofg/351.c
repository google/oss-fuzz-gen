#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <lcms2.h> // Assuming the function is part of the Little CMS library

int LLVMFuzzerTestOneInput_351(const uint8_t *data, size_t size) {
    // Initialize necessary variables
    cmsHANDLE handle;
    int row, col;

    // Ensure size is sufficient for extracting integers for row and col
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Create a fake IT8 handle for testing
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Extract row and column from the input data
    row = *((int*)data);
    col = *((int*)(data + sizeof(int)));

    // Call the function-under-test
    const char *result = cmsIT8GetDataRowCol(handle, row, col);

    // Print the result for debugging purposes
    if (result != NULL) {
        printf("Result: %s\n", result);
    }

    // Free the IT8 handle
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

    LLVMFuzzerTestOneInput_351(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
