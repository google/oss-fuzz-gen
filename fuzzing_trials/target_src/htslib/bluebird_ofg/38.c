#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
const char *hts_parse_reg(const char *, int *, int *);

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to contain a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the string and ensure it is null-terminated
    char *region_str = (char *)malloc(size + 1);
    if (region_str == NULL) {
        return 0;
    }
    memcpy(region_str, data, size);
    region_str[size] = '\0';

    // Initialize start and end integers
    int start = 0;
    int end = 0;

    // Call the function-under-test
    const char *result = hts_parse_reg(region_str, &start, &end);

    // Free allocated memory
    free(region_str);

    // Return 0 as required by LLVMFuzzerTestOneInput
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
