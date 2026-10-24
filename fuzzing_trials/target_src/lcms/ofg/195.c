#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_195(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < 2) {
        return 0;
    }

    // Create a handle for IT8
    cmsHANDLE it8Handle = cmsIT8Alloc(NULL);
    if (it8Handle == NULL) {
        return 0;
    }

    // Extract a null-terminated string from the data
    size_t strLength = size - 1;
    char *columnName = (char *)malloc(strLength + 1);
    if (columnName == NULL) {
        cmsIT8Free(it8Handle);
        return 0;
    }
    memcpy(columnName, data, strLength);
    columnName[strLength] = '\0';

    // Call the function-under-test
    cmsIT8SetIndexColumn(it8Handle, columnName);

    // Clean up
    free(columnName);
    cmsIT8Free(it8Handle);

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

    LLVMFuzzerTestOneInput_195(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
