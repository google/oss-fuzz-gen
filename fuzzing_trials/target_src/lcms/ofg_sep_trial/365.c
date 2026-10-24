#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_365(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for splitting data into multiple strings
    if (size < 4) return 0;

    // Create a dummy handle for cmsIT8SetPropertyMulti
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) return 0;

    // Split the input data into three non-null strings
    size_t part_size = size / 4;
    char str1[part_size + 1];
    char str2[part_size + 1];
    char str3[part_size + 1];

    memcpy(str1, data, part_size);
    str1[part_size] = '\0';
    memcpy(str2, data + part_size, part_size);
    str2[part_size] = '\0';
    memcpy(str3, data + 2 * part_size, part_size);
    str3[part_size] = '\0';

    // Call the function under test
    cmsBool result = cmsIT8SetPropertyMulti(handle, str1, str2, str3);

    // Clean up
    cmsIT8Free(handle);

    return 0;
}