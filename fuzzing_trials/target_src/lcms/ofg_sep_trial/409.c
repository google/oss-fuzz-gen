#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_409(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *comment;
    cmsBool result;

    // Initialize a valid cmsHANDLE
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Early exit if handle allocation fails
    }

    // Ensure the comment is null-terminated and non-NULL
    comment = (char *)malloc(size + 1);
    if (comment == NULL) {
        cmsIT8Free(handle);
        return 0; // Early exit if memory allocation fails
    }
    memcpy(comment, data, size);
    comment[size] = '\0'; // Null-terminate the comment

    // Call the function under test
    result = cmsIT8SetComment(handle, comment);

    // Clean up
    free(comment);
    cmsIT8Free(handle);

    return 0;
}