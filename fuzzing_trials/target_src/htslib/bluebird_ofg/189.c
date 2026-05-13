#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "htslib/sam.h" // Correct path where sam_hdr_parse is declared

int LLVMFuzzerTestOneInput_189(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for the string input
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        return 0;
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Call the function-under-test
    sam_hdr_t *result = sam_hdr_parse(size, input_str);

    // Clean up
    if (result != NULL) {
        sam_hdr_destroy(result); // Assuming there's a function to free sam_hdr_t
    }
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_189(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
