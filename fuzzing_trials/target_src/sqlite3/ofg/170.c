#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0;
    }

    // Split the input data into two strings and an integer
    size_t str1_len = data[0] % (size - 2);
    size_t str2_len = data[1] % (size - 2 - str1_len);
    int n = data[2] % (size - 2);

    const char *str1 = (const char *)(data + 3);
    const char *str2 = (const char *)(data + 3 + str1_len);

    // Ensure null-termination
    char *str1_copy = (char *)malloc(str1_len + 1);
    char *str2_copy = (char *)malloc(str2_len + 1);
    if (str1_copy == NULL || str2_copy == NULL) {
        free(str1_copy);
        free(str2_copy);
        return 0;
    }

    memcpy(str1_copy, str1, str1_len);
    memcpy(str2_copy, str2, str2_len);
    str1_copy[str1_len] = '\0';
    str2_copy[str2_len] = '\0';

    // Call the function-under-test
    int result = sqlite3_strnicmp(str1_copy, str2_copy, n);

    // Clean up
    free(str1_copy);
    free(str2_copy);

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

    LLVMFuzzerTestOneInput_170(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
