#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the strings
    if (size < 2) {
        return 0;
    }

    // Create a handle for the IT8 object
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Split the input data into two parts for the property name and value
    size_t half_size = size / 2;
    char *propertyName = (char *)malloc(half_size + 1);
    char *propertyValue = (char *)malloc(size - half_size + 1);

    if (propertyName == NULL || propertyValue == NULL) {
        cmsIT8Free(handle);
        free(propertyName);
        free(propertyValue);
        return 0;
    }

    // Copy the data into the strings and null-terminate them
    memcpy(propertyName, data, half_size);
    propertyName[half_size] = '\0';

    memcpy(propertyValue, data + half_size, size - half_size);
    propertyValue[size - half_size] = '\0';

    // Call the function-under-test
    cmsIT8SetPropertyStr(handle, propertyName, propertyValue);

    // Clean up
    cmsIT8Free(handle);
    free(propertyName);
    free(propertyValue);

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

    LLVMFuzzerTestOneInput_129(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
