#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHANDLE handle;
    int index;
    char format[256]; // Ensure the format string is not NULL

    // Check if the input size is large enough to extract necessary data
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Initialize the handle with a dummy IT8 handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Extract an integer index from the input data
    memcpy(&index, data, sizeof(int));
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the format string from the remaining input data
    size_t format_length = size < sizeof(format) ? size : sizeof(format) - 1;
    memcpy(format, data, format_length);
    format[format_length] = '\0'; // Null-terminate the string

    // Call the function-under-test
    cmsBool result = cmsIT8SetDataFormat(handle, index, format);

    // Free the allocated handle
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

    LLVMFuzzerTestOneInput_136(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
