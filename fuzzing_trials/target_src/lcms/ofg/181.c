#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_181(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract meaningful data
    if (size < 3) {
        return 0;
    }

    // Initialize a cmsHANDLE (for the sake of this example, we'll assume it's a pointer)
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Extract a portion of the data for the 'const char *' parameters
    size_t str_len1 = data[0] % (size - 2) + 1; // Ensure there's enough space for two strings
    size_t str_len2 = data[1] % (size - str_len1 - 1) + 1;

    char *str1 = (char *)malloc(str_len1 + 1);
    char *str2 = (char *)malloc(str_len2 + 1);

    if (str1 == NULL || str2 == NULL) {
        cmsIT8Free(handle);
        free(str1);
        free(str2);
        return 0;
    }

    memcpy(str1, data + 2, str_len1);
    str1[str_len1] = '\0';

    memcpy(str2, data + 2 + str_len1, str_len2);
    str2[str_len2] = '\0';

    // Use the remaining data as a cmsFloat64Number
    cmsFloat64Number dbl_value;
    if (size - 2 - str_len1 - str_len2 >= sizeof(cmsFloat64Number)) {
        memcpy(&dbl_value, data + 2 + str_len1 + str_len2, sizeof(cmsFloat64Number));
    } else {
        dbl_value = 0.0; // Default value if there's not enough data
    }

    // Call the function under test
    cmsBool result = cmsIT8SetDataDbl(handle, str1, str2, dbl_value);

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

    LLVMFuzzerTestOneInput_181(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
