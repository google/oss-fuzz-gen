#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>  // Include for malloc and free
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Ensure that the data is large enough to have at least two strings and an unsigned int
    if (size < 3) {
        return 0;
    }

    // Divide the data into two parts for string inputs and one part for options
    size_t str1_len = size / 3;
    size_t str2_len = size / 3;
    size_t options_offset = 2 * (size / 3);

    // Ensure null termination for the strings
    char *str1 = (char *)malloc(str1_len + 1);
    char *str2 = (char *)malloc(str2_len + 1);

    if (str1 == NULL || str2 == NULL) {
        free(str1);
        free(str2);
        return 0;
    }

    memcpy(str1, data, str1_len);
    str1[str1_len] = '\0';

    memcpy(str2, data + str1_len, str2_len);
    str2[str2_len] = '\0';

    // Extract options from the remaining data
    unsigned int options = 0;
    if (size > options_offset) {
        options = (unsigned int)data[options_offset];
    }

    // Call the function-under-test
    int result = sqlite3_strlike(str1, str2, options);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_117(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
