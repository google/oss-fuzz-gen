#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

// Define a non-NULL constant string for testing
#define NON_NULL_STRING "test_string"

int LLVMFuzzerTestOneInput_385(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    const char *property;
    const char *subproperty;
    const char *value;
    cmsBool result;

    // Initialize the handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure we have enough data to extract non-NULL strings
    if (size < 3) {
        cmsIT8Free(handle);
        return 0;
    }

    // Use parts of the data to create non-NULL strings
    property = NON_NULL_STRING;
    subproperty = NON_NULL_STRING;
    value = NON_NULL_STRING;

    // Call the function-under-test
    result = cmsIT8SetPropertyMulti(handle, property, subproperty, value);

    // Free the handle
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

    LLVMFuzzerTestOneInput_385(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
