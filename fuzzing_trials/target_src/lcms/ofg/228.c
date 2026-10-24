#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "lcms2_plugin.h" // Assuming this is the correct header for cmsIT8FindDataFormat

int LLVMFuzzerTestOneInput_228(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *format;

    // Ensure the input size is large enough to create a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Initialize the handle with a non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Allocate memory for the format string and copy the data into it
    format = (char *)malloc(size + 1);
    if (format == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(format, data, size);
    format[size] = '\0'; // Ensure null-termination

    // Call the function-under-test
    cmsIT8FindDataFormat(handle, format);

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

    LLVMFuzzerTestOneInput_228(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
