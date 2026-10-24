#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_257(const uint8_t *data, size_t size) {
    // Initialize parameters for cmsIT8SetDataRowCol
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure size is sufficient for extracting int values and a string
    if (size < 10) {
        cmsIT8Free(handle);
        return 0;
    }

    // Extract integers from data
    int row = (int)data[0];
    int col = (int)data[1];

    // Extract a string from the remaining data
    const char *strData = (const char *)(data + 2);
    size_t strSize = size - 2;

    // Ensure the string is null-terminated
    char *nullTerminatedStr = (char *)malloc(strSize + 1);
    if (nullTerminatedStr == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(nullTerminatedStr, strData, strSize);
    nullTerminatedStr[strSize] = '\0';

    // Call the function-under-test
    cmsBool result = cmsIT8SetDataRowCol(handle, row, col, nullTerminatedStr);

    // Clean up
    free(nullTerminatedStr);
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

    LLVMFuzzerTestOneInput_257(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
