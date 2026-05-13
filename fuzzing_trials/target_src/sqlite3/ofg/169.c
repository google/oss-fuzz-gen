#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Added for malloc and free
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_169(const uint8_t *data, size_t size) {
    // Ensure there is enough data for two strings and an integer
    if (size < 3) {
        return 0;
    }

    // Split the input data into two strings and an integer
    size_t str1_len = size / 3;
    size_t str2_len = size / 3;
    int cmp_length = (int)(size / 3);

    const char *str1 = (const char *)data;
    const char *str2 = (const char *)(data + str1_len);

    // Ensure the strings are null-terminated
    char *str1_null_terminated = (char *)malloc(str1_len + 1);
    char *str2_null_terminated = (char *)malloc(str2_len + 1);

    if (str1_null_terminated == NULL || str2_null_terminated == NULL) {
        free(str1_null_terminated);
        free(str2_null_terminated);
        return 0;
    }

    memcpy(str1_null_terminated, str1, str1_len);
    memcpy(str2_null_terminated, str2, str2_len);

    str1_null_terminated[str1_len] = '\0';
    str2_null_terminated[str2_len] = '\0';

    // Call the function-under-test
    int result = sqlite3_strnicmp(str1_null_terminated, str2_null_terminated, cmp_length);

    // Clean up
    free(str1_null_terminated);
    free(str2_null_terminated);

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

    LLVMFuzzerTestOneInput_169(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
