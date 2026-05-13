#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_177(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHANDLE handle;
    char key[256];
    char subkey[256];
    cmsFloat64Number value;

    // Ensure the data size is sufficient to extract meaningful inputs
    if (size < 2) return 0;

    // Initialize the handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) return 0;

    // Copy data into key and subkey ensuring null termination
    size_t key_len = size / 2 < 255 ? size / 2 : 255;
    size_t subkey_len = size / 2 < 255 ? size / 2 : 255;
    memcpy(key, data, key_len);
    key[key_len] = '\0';
    memcpy(subkey, data + key_len, subkey_len);
    subkey[subkey_len] = '\0';

    // Use a fixed value for cmsFloat64Number
    value = 1.23;

    // Call the function under test
    cmsIT8SetDataDbl(handle, key, subkey, value);

    // Free the handle
    cmsIT8Free(handle);

    return 0;
}