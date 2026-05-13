#include <stdint.h>
#include <stdlib.h>
#include <htslib/sam.h> // Correct path for sam.h
#include <string.h> // Include for memcpy

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = NULL;

    // Check if the size is greater than zero to avoid unnecessary operations
    if (size == 0) {
        return 0;
    }

    // Use the input data to create a SAM header
    // Create a null-terminated string from the input data
    char *sam_header_str = (char *)malloc(size + 1);
    if (sam_header_str == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(sam_header_str, data, size);
    sam_header_str[size] = '\0'; // Null-terminate the string

    // Attempt to parse the SAM header from the input data
    hdr = sam_hdr_parse(size, sam_header_str);
    free(sam_header_str);

    if (hdr == NULL) {
        return 0; // Exit if parsing fails
    }

    // Perform operations on the parsed header
    // For example, you can invoke functions that operate on the header
    // This is a placeholder for actual operations on the header
    // Example: int num_refs = sam_hdr_nref(hdr);

    // Clean up
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

    LLVMFuzzerTestOneInput_20(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
