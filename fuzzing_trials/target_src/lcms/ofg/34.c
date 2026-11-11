#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to split into three parts
    if (size < 3) return 0;

    // Initialize the LCMS handle
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) return 0;

    // Split the input data into three parts
    size_t part_size = size / 3;
    size_t remainder = size % 3;

    // Allocate memory for the strings and ensure null-termination
    char *str1 = (char *)malloc(part_size + 1);
    char *str2 = (char *)malloc(part_size + 1);
    char *str3 = (char *)malloc(part_size + remainder + 1);

    if (str1 == NULL || str2 == NULL || str3 == NULL) {
        cmsIT8Free(handle);
        free(str1);
        free(str2);
        free(str3);
        return 0;
    }

    memcpy(str1, data, part_size);
    memcpy(str2, data + part_size, part_size);
    memcpy(str3, data + 2 * part_size, part_size + remainder);

    str1[part_size] = '\0';
    str2[part_size] = '\0';
    str3[part_size + remainder] = '\0';

    // Call the function-under-test
    cmsBool result = cmsIT8SetData(handle, str1, str2, str3);

    // Clean up
    cmsIT8Free(handle);
    free(str1);
    free(str2);
    free(str3);

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

    LLVMFuzzerTestOneInput_34(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
