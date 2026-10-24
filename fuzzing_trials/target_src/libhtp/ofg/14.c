#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>  // Added for malloc and free

// Function-under-test declaration
int bstr_util_cmp_mem_nocasenorzero(const void *str1, size_t len1, const void *str2, size_t len2);

// Helper function to convert a buffer to lowercase
void to_lowercase(uint8_t *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = tolower(buffer[i]);
    }
}

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Ensure there is enough data to split into two non-empty strings
    if (size < 2) return 0;

    // Split the input data into two parts
    size_t len1 = size / 2;
    size_t len2 = size - len1;

    // Create buffers for the two strings
    uint8_t *str1 = (uint8_t *)malloc(len1 + 1);
    uint8_t *str2 = (uint8_t *)malloc(len2 + 1);

    if (str1 == NULL || str2 == NULL) {
        free(str1);
        free(str2);
        return 0;
    }

    // Copy data into the buffers and null-terminate
    memcpy(str1, data, len1);
    memcpy(str2, data + len1, len2);
    str1[len1] = '\0';
    str2[len2] = '\0';

    // Convert both strings to lowercase
    to_lowercase(str1, len1);
    to_lowercase(str2, len2);

    // Call the function-under-test
    int result = bstr_util_cmp_mem_nocasenorzero((const void *)str1, len1, (const void *)str2, len2);

    // Clean up
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
