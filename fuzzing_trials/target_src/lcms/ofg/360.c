#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "lcms2.h" // Assuming the header file for cmsIT8GetPatchName is included here

// Remove the extern "C" linkage specification for C code
int LLVMFuzzerTestOneInput_360(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    int index;
    char name[256]; // Allocate a buffer for the patch name

    // Initialize handle with a non-NULL value, assuming a function exists for this
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure size is large enough to extract an integer for index
    if (size < sizeof(int)) {
        cmsIT8Free(handle);
        return 0;
    }

    // Copy the first part of data into index
    memcpy(&index, data, sizeof(int));

    // Ensure the name buffer is not NULL
    strncpy(name, "default_name", sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0'; // Null-terminate the string

    // Call the function-under-test
    const char *result = cmsIT8GetPatchName(handle, index, name);

    // Clean up
    cmsIT8Free(handle);

    // The result is not used further, as we are just testing for crashes
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

    LLVMFuzzerTestOneInput_360(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
