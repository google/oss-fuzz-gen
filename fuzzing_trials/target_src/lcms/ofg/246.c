#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_246(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to split into parts
    if (size < sizeof(cmsUInt32Number) + 1) {
        return 0;
    }

    // Initialize a handle for the IT8 data
    cmsHANDLE handle = cmsIT8Alloc(cmsCreateContext(NULL, NULL));
    if (handle == NULL) {
        return 0;
    }

    // Extract a cmsUInt32Number from the input data
    cmsUInt32Number hexValue;
    memcpy(&hexValue, data, sizeof(cmsUInt32Number));

    // Extract a string (const char*) from the input data
    size_t stringSize = size - sizeof(cmsUInt32Number);
    char *propertyName = (char *)malloc(stringSize + 1);
    if (propertyName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(propertyName, data + sizeof(cmsUInt32Number), stringSize);
    propertyName[stringSize] = '\0'; // Null-terminate the string

    // Call the function-under-test
    cmsBool result = cmsIT8SetPropertyHex(handle, propertyName, hexValue);

    // Clean up
    free(propertyName);
    cmsIT8Free(handle);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_246(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
