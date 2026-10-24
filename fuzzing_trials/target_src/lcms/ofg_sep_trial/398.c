#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_398(const uint8_t *data, size_t size) {
    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *filename = (char *)malloc(size + 1);
    if (filename == NULL) {
        cmsDeleteContext(context);
        return 0;
    }
    memcpy(filename, data, size);
    filename[size] = '\0';

    // Call the function-under-test
    cmsHANDLE handle = cmsIT8LoadFromFile(context, filename);

    // Cleanup
    if (handle != NULL) {
        cmsIT8Free(handle);
    }
    free(filename);
    cmsDeleteContext(context);

    return 0;
}