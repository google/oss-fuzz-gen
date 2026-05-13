#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_408(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *comment;
    cmsBool result;

    // Initialize handle using cmsIT8Alloc
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Allocate memory for the comment and ensure it is null-terminated
    comment = (char *)malloc(size + 1);
    if (comment == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(comment, data, size);
    comment[size] = '\0';

    // Call the function-under-test
    result = cmsIT8SetComment(handle, comment);

    // Clean up
    free(comment);
    cmsIT8Free(handle);

    return 0;
}