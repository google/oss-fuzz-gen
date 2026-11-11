#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for the parameters
    if (size < 5) {
        return 0;
    }

    // Initialize the parameters for cmsIT8SetDataFormat
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    int index = data[0]; // Use the first byte for the index

    // Use the rest of the data as a string for the third parameter
    char format[256];
    size_t format_size = (size - 1) < 255 ? (size - 1) : 255;
    memcpy(format, &data[1], format_size);
    format[format_size] = '\0'; // Ensure null-termination

    // Call the function under test
    cmsBool result = cmsIT8SetDataFormat(handle, index, format);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}