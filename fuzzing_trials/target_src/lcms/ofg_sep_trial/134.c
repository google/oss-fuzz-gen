#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsIOHANDLER *iohandler = NULL;
    char filename[256];
    char mode[4];

    // Ensure data is large enough to contain at least some filename and mode
    if (size < 2) {
        return 0;
    }

    // Initialize context (for simplicity, using NULL as a placeholder)
    context = NULL;

    // Copy data into filename and mode, ensuring null-termination
    size_t filename_len = size > 255 ? 255 : size;
    strncpy(filename, (const char *)data, filename_len);
    filename[filename_len] = '\0';

    // Use a simple mode for testing, e.g., "r" for read
    strncpy(mode, "r", 2);
    mode[1] = '\0';

    // Call the function-under-test
    iohandler = cmsOpenIOhandlerFromFile(context, filename, mode);

    // Clean up if iohandler was successfully created
    if (iohandler != NULL) {
        cmsCloseIOhandler(iohandler);
    }

    return 0;
}