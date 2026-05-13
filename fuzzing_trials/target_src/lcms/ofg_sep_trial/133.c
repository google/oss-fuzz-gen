#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Ensure the data is null-terminated for string usage
    char *filename = (char *)malloc(size + 1);
    if (filename == NULL) {
        cmsDeleteContext(context);
        return 0;
    }
    memcpy(filename, data, size);
    filename[size] = '\0';

    // Use a fixed mode for testing purposes
    const char *mode = "r"; // Read mode

    // Call the function-under-test
    cmsIOHANDLER *handler = cmsOpenIOhandlerFromFile(context, filename, mode);

    // Clean up
    if (handler != NULL) {
        cmsCloseIOhandler(handler);
    }
    free(filename);
    cmsDeleteContext(context);

    return 0;
}