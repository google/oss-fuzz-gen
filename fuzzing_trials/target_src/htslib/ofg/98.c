#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>  // Include for malloc and free
#include <string.h>

// Function-under-test declaration
const char *hts_parse_reg(const char *region, int *beg, int *end);

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated
    char *region = (char *)malloc(size + 1);
    if (region == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(region, data, size);
    region[size] = '\0';

    // Initialize begin and end pointers
    int beg = 0;
    int end = 0;

    // Call the function-under-test
    const char *result = hts_parse_reg(region, &beg, &end);

    // Print the result and parsed values for debugging purposes
    printf("Result: %s, Begin: %d, End: %d\n", result ? result : "NULL", beg, end);

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

    LLVMFuzzerTestOneInput_98(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
