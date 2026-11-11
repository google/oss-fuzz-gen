#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern char *sam_open_mode_opts(const char *, const char *, const char *);

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to split into three parts
    if (size < 3) {
        return 0;
    }

    // Allocate memory for the three strings, ensuring null termination
    size_t part_size = size / 3;
    char *str1 = (char *)malloc(part_size + 1);
    char *str2 = (char *)malloc(part_size + 1);
    char *str3 = (char *)malloc(size - 2 * part_size + 1);

    if (str1 == NULL || str2 == NULL || str3 == NULL) {
        free(str1);
        free(str2);
        free(str3);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(str1, data, part_size);
    str1[part_size] = '\0';

    memcpy(str2, data + part_size, part_size);
    str2[part_size] = '\0';

    memcpy(str3, data + 2 * part_size, size - 2 * part_size);
    str3[size - 2 * part_size] = '\0';

    // Call the function-under-test
    char *result = sam_open_mode_opts(str1, str2, str3);

    // Free the allocated memory
    free(str1);
    free(str2);
    free(str3);

    // If the function returns a dynamically allocated string, free it
    free(result);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
