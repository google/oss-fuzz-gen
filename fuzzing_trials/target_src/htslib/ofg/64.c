#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h> // Include this for PRId64

typedef int64_t hts_pos_t;

extern const char *hts_parse_reg64(const char *region, hts_pos_t *beg, hts_pos_t *end);

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated for string operations
    char *region = (char *)malloc(size + 1);
    if (region == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(region, data, size);
    region[size] = '\0';

    hts_pos_t beg = 0;
    hts_pos_t end = 0;

    // Fuzz the hts_parse_reg64 function
    const char *result = hts_parse_reg64(region, &beg, &end);

    // Use the result to prevent compiler optimizations
    if (result != NULL) {
        printf("Parsed region: %s, beg: %" PRId64 ", end: %" PRId64 "\n", result, beg, end);
    }

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

    LLVMFuzzerTestOneInput_64(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
