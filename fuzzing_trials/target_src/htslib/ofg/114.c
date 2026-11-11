#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/htslib/htslib/sam.h" // Correct path for sam.h

int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for processing
    if (size < 2) {
        return 0;
    }

    // Declare and initialize variables
    sam_hdr_t *hdr = sam_hdr_init(); // Assuming sam_hdr_init() initializes a sam_hdr_t object

    // Ensure the header is not NULL
    if (hdr == NULL) {
        return 0;
    }

    // Use part of the input data to create dynamic key and value
    // This will allow the fuzzer to generate different keys and values
    size_t key_len = data[0] % (size - 1) + 1; // Ensure key_len is at least 1
    size_t value_len = size - key_len - 1; // Remaining data for value

    char *key = (char *)malloc(key_len + 1);
    char *value = (char *)malloc(value_len + 1);

    if (key == NULL || value == NULL) {
        sam_hdr_destroy(hdr);
        free(key);
        free(value);
        return 0;
    }

    memcpy(key, data + 1, key_len);
    key[key_len] = '\0'; // Null-terminate the key

    memcpy(value, data + 1 + key_len, value_len);
    value[value_len] = '\0'; // Null-terminate the value

    // Call the function-under-test
    int result = sam_hdr_change_HD(hdr, key, value);

    // Clean up
    sam_hdr_destroy(hdr);
    free(key);
    free(value);

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

    LLVMFuzzerTestOneInput_114(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
