#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    // Ensure there is enough data for at least two strings
    if (size < 2) return 0;

    // Initialize a cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) return 0;

    // Split the input data into two parts for property and value strings
    size_t half_size = size / 2;
    char *property = (char *)malloc(half_size + 1);
    char *value = (char *)malloc(size - half_size + 1);

    if (property == NULL || value == NULL) {
        free(property);
        free(value);
        cmsIT8Free(handle);
        return 0;
    }

    // Copy data into property and value, ensuring null termination
    memcpy(property, data, half_size);
    property[half_size] = '\0';
    memcpy(value, data + half_size, size - half_size);
    value[size - half_size] = '\0';

    // Call the function-under-test
    cmsIT8SetPropertyStr(handle, property, value);

    // Clean up
    free(property);
    free(value);
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

    LLVMFuzzerTestOneInput_128(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
