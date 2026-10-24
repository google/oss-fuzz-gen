#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming cmsHANDLE is a pointer type, for example:
typedef void* cmsHANDLE;

// Mock function for cmsIT8GetPropertyMulti_491, replace with actual function
const char* cmsIT8GetPropertyMulti_491(cmsHANDLE handle, const char* property, const char* subkey) {
    // Mock implementation
    return "MockedPropertyValue";
}

int LLVMFuzzerTestOneInput_491(const uint8_t *data, size_t size) {
    // Ensure that data is large enough to be used for strings
    if (size < 2) {
        return 0;
    }

    // Initialize the parameters
    cmsHANDLE handle = (cmsHANDLE)0x1;  // Mock handle, replace with actual initialization if needed

    // Split the data into two parts for property and subkey strings
    size_t half_size = size / 2;
    char* property = (char*)malloc(half_size + 1);
    char* subkey = (char*)malloc(size - half_size + 1);

    if (property == NULL || subkey == NULL) {
        free(property);
        free(subkey);
        return 0;
    }

    // Copy data into property and subkey, ensuring null termination
    memcpy(property, data, half_size);
    property[half_size] = '\0';

    memcpy(subkey, data + half_size, size - half_size);
    subkey[size - half_size] = '\0';

    // Call the function-under-test
    const char* result = cmsIT8GetPropertyMulti_491(handle, property, subkey);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result != NULL) {
        printf("Result: %s\n", result);
    }

    // Clean up
    free(property);
    free(subkey);

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

    LLVMFuzzerTestOneInput_491(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
