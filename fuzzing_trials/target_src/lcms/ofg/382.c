#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Function-under-test declaration
int cmsstrcasecmp(const char *s1, const char *s2);

int LLVMFuzzerTestOneInput_382(const uint8_t *data, size_t size) {
    // Ensure there's enough data to create two strings
    if (size < 2) {
        return 0;
    }

    // Calculate the length of each string, ensuring at least one character and a null terminator
    size_t len1 = size / 2;
    size_t len2 = size - len1;

    // Allocate memory for the strings
    char *str1 = (char *)malloc(len1 + 1);
    char *str2 = (char *)malloc(len2 + 1);

    if (str1 == NULL || str2 == NULL) {
        free(str1);
        free(str2);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(str1, data, len1);
    str1[len1] = '\0';

    memcpy(str2, data + len1, len2);
    str2[len2] = '\0';

    // Call the function-under-test
    cmsstrcasecmp(str1, str2);

    // Free the allocated memory
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

    LLVMFuzzerTestOneInput_382(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
