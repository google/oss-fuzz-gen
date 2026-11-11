#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Function-under-test declaration
int cmsstrcasecmp(const char *s1, const char *s2);

int LLVMFuzzerTestOneInput_383(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for two non-empty strings
    if (size < 2) {
        return 0;
    }

    // Allocate memory for two strings
    char *str1 = (char *)malloc(size + 1);
    char *str2 = (char *)malloc(size + 1);

    if (str1 == NULL || str2 == NULL) {
        // Memory allocation failed
        free(str1);
        free(str2);
        return 0;
    }

    // Split the input data into two strings
    size_t mid = size / 2;
    memcpy(str1, data, mid);
    str1[mid] = '\0';  // Null-terminate the first string

    memcpy(str2, data + mid, size - mid);
    str2[size - mid] = '\0';  // Null-terminate the second string

    // Call the function-under-test
    int result = cmsstrcasecmp(str1, str2);

    // Clean up
    free(str1);
    free(str2);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_383(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
