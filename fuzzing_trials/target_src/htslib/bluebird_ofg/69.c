#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Function-under-test declaration
int sam_open_mode(char *, const char *, const char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to split into three parts
    if (size < 3) {
        return 0;
    }

    // Calculate the lengths for each parameter
    size_t len1 = size / 3;
    size_t len2 = size / 3;
    size_t len3 = size - len1 - len2;

    // Ensure that each parameter has enough space for the data and a null terminator
    if (len1 >= 256 || len2 >= 256 || len3 >= 256) {
        return 0;
    }

    // Allocate memory for the parameters
    char param1[256];
    char param2[256];
    char param3[256];

    // Copy data to each parameter, ensuring null-termination
    memcpy(param1, data, len1);
    param1[len1] = '\0';

    memcpy(param2, data + len1, len2);
    param2[len2] = '\0';

    memcpy(param3, data + len1 + len2, len3);
    param3[len3] = '\0';

    // Call the function-under-test
    sam_open_mode(param1, param2, param3);

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

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
