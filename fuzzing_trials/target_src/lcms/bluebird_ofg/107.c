#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Initialize a cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Extract integers for row and column
    int row = *((int *)data);
    int col = *((int *)(data + sizeof(int)));

    // Extract a string for the data
    const char *strData = (const char *)(data + sizeof(int) * 2);
    size_t strSize = size - sizeof(int) * 2;

    // Ensure the string is null-terminated
    char *strCopy = (char *)malloc(strSize + 1);
    if (strCopy == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(strCopy, strData, strSize);
    strCopy[strSize] = '\0';

    // Call the function-under-test
    cmsIT8SetDataRowCol(handle, row, col, strCopy);

    // Clean up
    free(strCopy);
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

    LLVMFuzzerTestOneInput_107(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
