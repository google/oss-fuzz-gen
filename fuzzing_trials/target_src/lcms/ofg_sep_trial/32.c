#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2_plugin.h>

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char key[256];
    char subkey[256];
    char value[256];

    // Initialize handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the data is large enough to fill key, subkey, and value
    if (size < 768) {
        cmsIT8Free(handle);
        return 0;
    }

    // Copy data into key, subkey, and value, ensuring null termination
    memcpy(key, data, 255);
    key[255] = '\0';

    memcpy(subkey, data + 256, 255);
    subkey[255] = '\0';

    memcpy(value, data + 512, 255);
    value[255] = '\0';

    // Call the function-under-test
    cmsBool result = cmsIT8SetData(handle, key, subkey, value);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}