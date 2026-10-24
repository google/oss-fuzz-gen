#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_277(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    const char *propertyName;
    const char *result;

    // Initialize a cmsHANDLE for testing
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the input data is null-terminated for string operations
    char *nullTerminatedData = (char *)malloc(size + 1);
    if (nullTerminatedData == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy(nullTerminatedData, data, size);
    nullTerminatedData[size] = '\0';

    // Use the null-terminated data as the property name
    propertyName = nullTerminatedData;

    // Call the function-under-test
    result = cmsIT8GetProperty(handle, propertyName);

    // Clean up
    free(nullTerminatedData);
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

    LLVMFuzzerTestOneInput_277(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
