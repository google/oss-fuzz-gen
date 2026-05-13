#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    int index;
    char *format;

    // Ensure size is sufficient for splitting into parts
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Initialize the handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Extract the integer index from the data
    index = *((int*)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Allocate and copy the remaining data to format string
    format = (char *)malloc(size + 1);
    if (format == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(format, data, size);
    format[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    cmsIT8SetDataFormat(handle, index, format);

    // Clean up
    free(format);
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

    LLVMFuzzerTestOneInput_137(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
