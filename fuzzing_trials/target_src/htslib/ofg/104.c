#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern long long hts_parse_decimal(const char *, char **, int);

int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(str, data, size);
    str[size] = '\0';

    // Prepare a pointer for the endptr parameter
    char *endptr = NULL;

    // Call the function-under-test with various base values
    for (int base = 2; base <= 36; base++) {
        hts_parse_decimal(str, &endptr, base);
    }

    // Free the allocated memory
    free(str);

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

    LLVMFuzzerTestOneInput_104(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
