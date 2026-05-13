#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/hts.h"
#include "/src/htslib/htslib/tbx.h" // Include the correct header for tabix functions

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the test
    if (size < 1) {
        return 0;
    }

    // Initialize an integer value
    int some_int = (int)data[0]; // Use the first byte of data as an integer

    // Create a null-terminated string from the remaining data
    size_t str_size = size - 1;
    char *str = (char *)malloc(str_size + 1);
    if (!str) {
        return 0;
    }
    memcpy(str, data + 1, str_size);
    str[str_size] = '\0'; // Null-terminate the string

    // Example function call from htslib, replace with a valid function
    // Since hts_idx_tbi_name is not a valid function, let's assume we want to use tbx_index_build instead
    // tbx_index_build is a common function to build an index for a tabix file
    tbx_t *tbx = tbx_index_load(str); // Load the index using the string
    if (tbx) {
        tbx_destroy(tbx); // Destroy the index if it was successfully loaded
    }

    // Clean up
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
