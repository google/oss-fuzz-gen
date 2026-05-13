#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_194(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for a null-terminated string
    if (size < 2) return 0;

    // Create a dummy cmsHANDLE for testing
    cmsHANDLE handle = cmsIT8Alloc(cmsCreateContext(NULL, NULL));
    if (handle == NULL) return 0;

    // Allocate memory for the column name and ensure it's null-terminated
    char *columnName = (char *)malloc(size + 1);
    if (columnName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(columnName, data, size);
    columnName[size] = '\0';

    // Call the function-under-test
    cmsBool result = cmsIT8SetIndexColumn(handle, columnName);

    // Clean up
    free(columnName);
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

    LLVMFuzzerTestOneInput_194(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
