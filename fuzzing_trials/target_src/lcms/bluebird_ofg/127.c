#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // Include stdlib.h for malloc and free
#include "lcms2.h" // Assuming lcms2.h is the correct header for the function

// Remove extern "C" since this is not valid in C code
int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for splitting into two strings
    if (size < 2) return 0;

    // Initialize a cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) return 0;

    // Split the input data into two strings
    size_t half_size = size / 2;
    char *property = (char *)malloc(half_size + 1);
    char *value = (char *)malloc(size - half_size + 1);

    if (property == NULL || value == NULL) {
        if (property) free(property);
        if (value) free(value);
        cmsIT8Free(handle);
        return 0;
    }

    memcpy(property, data, half_size);
    property[half_size] = '\0';

    memcpy(value, data + half_size, size - half_size);
    value[size - half_size] = '\0';

    // Call the function-under-test
    cmsBool result = cmsIT8SetPropertyUncooked(handle, property, value);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
