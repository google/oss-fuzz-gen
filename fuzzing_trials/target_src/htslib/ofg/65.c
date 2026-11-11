#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int64_t hts_pos_t;

// Function signature
const char * hts_parse_reg64(const char *region, hts_pos_t *beg, hts_pos_t *end);

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Ensure that the input data is null-terminated and has a non-zero size
    if (size == 0) return 0;

    // Allocate memory for the region string and ensure it's null-terminated
    char *region = (char *)malloc(size + 1);
    if (region == NULL) return 0;
    memcpy(region, data, size);
    region[size] = '\0';

    // Initialize beg and end pointers
    hts_pos_t beg = 0;
    hts_pos_t end = 0;

    // Call the function-under-test
    const char *result = hts_parse_reg64(region, &beg, &end);

    // Free allocated memory
    free(region);

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

    LLVMFuzzerTestOneInput_65(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
