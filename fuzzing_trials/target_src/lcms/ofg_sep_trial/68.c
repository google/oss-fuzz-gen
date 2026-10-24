#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the function parameters
    if (size < sizeof(cmsUInt32Number) + 1) {
        return 0;
    }

    // Initialize cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Extract cmsUInt32Number from data
    cmsUInt32Number memSize = *(const cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Ensure memSize does not exceed remaining data size
    if (memSize > size) {
        memSize = (cmsUInt32Number)size;
    }

    // Allocate memory and copy data into it
    void *memPtr = malloc(memSize);
    if (memPtr == NULL) {
        cmsDeleteContext(context);
        return 0;
    }
    memcpy(memPtr, data, memSize);

    // Extract a null-terminated string from the remaining data
    const char *access = (const char *)data;
    size_t accessLength = strnlen(access, size);
    if (accessLength == size) {
        access = "r"; // Default to read mode if no null-terminator found
    }

    // Call the function under test
    cmsIOHANDLER *handler = cmsOpenIOhandlerFromMem(context, memPtr, memSize, access);

    // Clean up
    if (handler != NULL) {
        cmsCloseIOhandler(handler);
    }
    free(memPtr);
    cmsDeleteContext(context);

    return 0;
}