#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for safe string operations
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        return 0; // Memory allocation failed, gracefully exit
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0'; // Null-terminate the string

    htsFormat format;
    int result = hts_parse_format(&format, input_str);

    // Clean up
    free(input_str);

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

    LLVMFuzzerTestOneInput_81(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
