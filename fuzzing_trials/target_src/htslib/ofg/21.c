#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <htslib/sam.h> // Include the relevant header for sam_hdr_t

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = NULL;

    // Ensure that the data is not empty and is of a reasonable size
    if (size > 0) {
        // Allocate memory for sam_hdr_t and initialize it
        hdr = sam_hdr_init();
        if (hdr == NULL) {
            return 0; // If allocation fails, exit early
        }

        // Simulate filling the header with data
        char *header_data = (char *)malloc(size + 1);
        if (header_data == NULL) {
            sam_hdr_destroy(hdr);
            return 0;
        }
        memcpy(header_data, data, size);
        header_data[size] = '\0';

        // Attempt to parse the header data into the sam_hdr_t structure
        sam_hdr_t *parsed_hdr = sam_hdr_parse(size, header_data);
        if (parsed_hdr == NULL) {
            // If parsing fails, clean up and exit
            free(header_data);
            sam_hdr_destroy(hdr);
            return 0;
        }

        // Further processing can be done here if needed
        // For example, you might want to test other functions that use the header

        free(header_data);
        sam_hdr_destroy(parsed_hdr);
    }

    // Call the function-under-test
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

    LLVMFuzzerTestOneInput_21(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
