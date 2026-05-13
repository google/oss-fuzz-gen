#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern char * sam_open_mode_opts(const char *, const char *, const char *);

int LLVMFuzzerTestOneInput_197(const uint8_t *data, size_t size) {
    // Ensure the size is enough to split into three non-null strings
    if (size < 3) {
        return 0;
    }

    // Split the input data into three parts
    size_t part_size = size / 3;
    size_t remaining = size % 3;

    // Allocate memory for the three strings
    char *arg1 = (char *)malloc(part_size + 1);
    char *arg2 = (char *)malloc(part_size + 1);
    char *arg3 = (char *)malloc(part_size + remaining + 1);

    if (arg1 == NULL || arg2 == NULL || arg3 == NULL) {
        free(arg1);
        free(arg2);
        free(arg3);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(arg1, data, part_size);
    arg1[part_size] = '\0';

    memcpy(arg2, data + part_size, part_size);
    arg2[part_size] = '\0';

    memcpy(arg3, data + 2 * part_size, part_size + remaining);
    arg3[part_size + remaining] = '\0';

    // Call the function-under-test
    char *result = sam_open_mode_opts(arg1, arg2, arg3);

    // Free the result if it was dynamically allocated
    free(result);

    // Free the allocated memory
    free(arg1);
    free(arg2);
    free(arg3);

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

    LLVMFuzzerTestOneInput_197(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
