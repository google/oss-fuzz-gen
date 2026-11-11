#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_296(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the strings
    if (size < 3) {
        return 0;
    }

    // Create a cmsHANDLE, assuming cmsIT8Alloc() is the correct way to allocate it
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Split the input data into two strings
    size_t str1_len = data[0] % size;
    size_t str2_len = (data[1] % (size - str1_len)) + 1;
    size_t str3_len = (data[2] % (size - str1_len - str2_len)) + 1;

    char *str1 = (char *)malloc(str1_len + 1);
    char *str2 = (char *)malloc(str2_len + 1);
    char *str3 = (char *)malloc(str3_len + 1);

    if (str1 == NULL || str2 == NULL || str3 == NULL) {
        free(str1);
        free(str2);
        free(str3);
        cmsIT8Free(handle);
        return 0;
    }

    memcpy(str1, data + 3, str1_len);
    memcpy(str2, data + 3 + str1_len, str2_len);
    memcpy(str3, data + 3 + str1_len + str2_len, str3_len);

    str1[str1_len] = '\0';
    str2[str2_len] = '\0';
    str3[str3_len] = '\0';

    // Call the function-under-test
    cmsFloat64Number result = cmsIT8GetDataDbl(handle, str1, str2);

    // Clean up
    free(str1);
    free(str2);
    free(str3);
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

    LLVMFuzzerTestOneInput_296(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
