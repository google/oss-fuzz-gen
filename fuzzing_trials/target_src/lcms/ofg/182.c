#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_182(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for splitting into components
    if (size < 3) {
        return 0;
    }

    // Initialize the components from the input data
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Split the input data into parts for the string arguments
    size_t str1_len = data[0] % (size - 2) + 1; // Ensure non-zero length
    size_t str2_len = data[1] % (size - str1_len - 1) + 1; // Ensure non-zero length

    char *str1 = (char *)malloc(str1_len + 1);
    char *str2 = (char *)malloc(str2_len + 1);
    if (str1 == NULL || str2 == NULL) {
        cmsIT8Free(handle);
        free(str1);
        free(str2);
        return 0;
    }

    memcpy(str1, data + 2, str1_len);
    str1[str1_len] = '\0';

    memcpy(str2, data + 2 + str1_len, str2_len);
    str2[str2_len] = '\0';

    // Use the remaining data to construct a cmsFloat64Number
    cmsFloat64Number value;
    if (size >= 2 + str1_len + str2_len + sizeof(cmsFloat64Number)) {
        memcpy(&value, data + 2 + str1_len + str2_len, sizeof(cmsFloat64Number));
    } else {
        value = 0.0; // Default value if insufficient data
    }

    // Call the function-under-test
    cmsIT8SetDataDbl(handle, str1, str2, value);

    // Clean up
    cmsIT8Free(handle);
    free(str1);
    free(str2);

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

    LLVMFuzzerTestOneInput_182(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
