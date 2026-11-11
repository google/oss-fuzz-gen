#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "htslib/sam.h"  // Assuming the sam_hdr_t type is defined in this library

int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Initialize variables
    sam_hdr_t *hdr = sam_hdr_init();

    // Ensure the hdr is not NULL
    if (hdr == NULL || size < 2) {
        return 0;
    }

    // Extract key and value from the input data
    // Ensure that the input data is large enough to provide both key and value
    size_t key_len = data[0] % (size - 1);  // Ensure key_len is within bounds
    size_t value_len = size - 1 - key_len;  // Remaining bytes for value

    if (key_len == 0 || value_len == 0) {
        return 0;
    }

    char *key = (char *)malloc(key_len + 1);
    char *value = (char *)malloc(value_len + 1);

    if (key == NULL || value == NULL) {
        free(key);
        free(value);
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Copy key and value from data
    memcpy(key, data + 1, key_len);
    key[key_len] = '\0';
    memcpy(value, data + 1 + key_len, value_len);
    value[value_len] = '\0';

    // Call the function-under-test
    int result = sam_hdr_change_HD(hdr, key, value);

    // Clean up
    free(key);
    free(value);
    sam_hdr_destroy(hdr);

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

    LLVMFuzzerTestOneInput_113(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
