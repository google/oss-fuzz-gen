#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_358(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    cmsUInt32Number tableIndex;

    // Check if the size is sufficient to extract a cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize a cmsHANDLE
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Extract a cmsUInt32Number from the data
    tableIndex = *(const cmsUInt32Number *)data;

    // Call the function-under-test
    cmsInt32Number result = cmsIT8SetTable(handle, tableIndex);

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

    LLVMFuzzerTestOneInput_358(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
