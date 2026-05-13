#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *propertyName;
    cmsFloat64Number propertyValue;
    cmsBool result;

    // Initialize the handle
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the data is large enough to extract meaningful inputs
    if (size < sizeof(cmsFloat64Number) + 1) {
        cmsIT8Free(handle);
        return 0;
    }

    // Allocate memory for the property name and ensure it's null-terminated
    propertyName = (char *)malloc(size - sizeof(cmsFloat64Number) + 1);
    if (propertyName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(propertyName, data, size - sizeof(cmsFloat64Number));
    propertyName[size - sizeof(cmsFloat64Number)] = '\0';

    // Extract the property value from the data
    memcpy(&propertyValue, data + size - sizeof(cmsFloat64Number), sizeof(cmsFloat64Number));

    // Call the function-under-test
    result = cmsIT8SetPropertyDbl(handle, propertyName, propertyValue);

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

    LLVMFuzzerTestOneInput_40(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
