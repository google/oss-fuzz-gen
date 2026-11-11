#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2_plugin.h"
#include "lcms2.h" // Include the main Little CMS library

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *propertyName;
    cmsFloat64Number result;

    // Initialize handle with a valid cmsHANDLE object
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Exit if handle allocation fails
    }

    // Ensure size is sufficient for a null-terminated string
    if (size < 1) {
        cmsIT8Free(handle);
        return 0;
    }

    // Allocate memory for propertyName and copy data into it
    propertyName = (char *)malloc(size + 1);
    if (propertyName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(propertyName, data, size);
    propertyName[size] = '\0'; // Null-terminate the string

    // Set a property to ensure the handle has data to work with
    cmsIT8SetPropertyDbl(handle, propertyName, 42.0);

    // Call the function-under-test
    result = cmsIT8GetPropertyDbl(handle, propertyName);

    // Clean up
    free(propertyName);
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
