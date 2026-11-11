#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_234(const uint8_t *data, size_t size) {
    // Allocate memory for sam_hdr_t
    sam_hdr_t *hdr = sam_hdr_init();

    if (hdr == NULL) {
        return 0;
    }

    // Create a temporary buffer to hold the input data
    char *temp_data = (char *)malloc(size + 1);
    if (temp_data == NULL) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Copy the input data into the temporary buffer and null-terminate it
    memcpy(temp_data, data, size);
    temp_data[size] = '\0';

    // Parse the header from the temporary buffer
    sam_hdr_t *parsed_hdr = sam_hdr_parse(size, temp_data);
    if (parsed_hdr != NULL) {
        // Call the function-under-test
        const char *result = sam_hdr_str(parsed_hdr);
        
        // Print the result for debugging purposes
        if (result != NULL) {
            printf("Header String: %s\n", result);
        }

        // Clean up the parsed header
        sam_hdr_destroy(parsed_hdr);
    }

    // Clean up
    free(temp_data);
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

    LLVMFuzzerTestOneInput_234(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
