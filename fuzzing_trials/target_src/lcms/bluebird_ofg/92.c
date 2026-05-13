#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"  // Include the main lcms2 library for the required functions

int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to be split into two strings
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for the two string parameters
    size_t half_size = size / 2;
    char *propertyName = (char *)malloc(half_size + 1);
    char *subPropertyName = (char *)malloc(size - half_size + 1);

    if (!propertyName || !subPropertyName) {
        free(propertyName);
        free(subPropertyName);
        return 0;
    }

    memcpy(propertyName, data, half_size);
    propertyName[half_size] = '\0';

    memcpy(subPropertyName, data + half_size, size - half_size);
    subPropertyName[size - half_size] = '\0';

    // Initialize a dummy cmsHANDLE for testing
    cmsHANDLE handle = cmsIT8Alloc(0);
    if (!handle) {
        free(propertyName);
        free(subPropertyName);
        return 0;
    }

    // Call the function-under-test
    const char *result = cmsIT8GetPropertyMulti(handle, propertyName, subPropertyName);

    // Clean up
    cmsIT8Free(handle);
    free(propertyName);
    free(subPropertyName);

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

    LLVMFuzzerTestOneInput_92(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
