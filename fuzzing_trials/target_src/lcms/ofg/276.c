#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"         // Include the main LittleCMS header for necessary types and functions
#include "lcms2_plugin.h"  // Assuming the header file where cmsIT8GetProperty is declared

// Ensure the LittleCMS library is linked correctly by including the correct header
// and ensuring the library is linked during compilation.

int LLVMFuzzerTestOneInput_276(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char propertyName[256];

    // Initialize handle to a non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure propertyName is NULL-terminated and non-NULL
    size_t copySize = size < 255 ? size : 255;
    memcpy(propertyName, data, copySize);
    propertyName[copySize] = '\0';

    // Add some setup for the handle to ensure meaningful context
    // For example, setting a known property if needed by the function
    // Use a correct function to set the property
    cmsIT8SetData(handle, "SAMPLE_PROPERTY", "SAMPLE_VALUE", "SampleValue");

    // Call the function-under-test
    const char *result = cmsIT8GetProperty(handle, propertyName);

    // Check the result to ensure it is being processed
    if (result != NULL) {
        printf("Property value: %s\n", result);
    }

    // Cleanup
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

    LLVMFuzzerTestOneInput_276(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
