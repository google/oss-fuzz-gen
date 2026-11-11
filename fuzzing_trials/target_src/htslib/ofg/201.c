#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "htslib/sam.h"

// Mock function to create a sam_hdr_t object
sam_hdr_t* create_sam_hdr() {
    // In a real scenario, you would populate this with actual data
    sam_hdr_t* hdr = sam_hdr_init();
    return hdr;
}

int LLVMFuzzerTestOneInput_201(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < 2) return 0;

    // Create a sam_hdr_t object
    sam_hdr_t *hdr = create_sam_hdr();
    if (hdr == NULL) return 0;

    // Use part of the data as a string for the second parameter
    size_t str_size = size / 2;
    char *str = (char *)malloc(str_size + 1);
    if (str == NULL) {
        sam_hdr_destroy(hdr);
        return 0;
    }
    memcpy(str, data, str_size);
    str[str_size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    sam_hdr_add_pg(hdr, str, NULL);

    // Clean up
    free(str);
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

    LLVMFuzzerTestOneInput_201(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
