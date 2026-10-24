#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "htslib/sam.h" // Correct path to the sam.h header

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = NULL;

    // Ensure there's data to parse
    if (size > 0) {
        // Attempt to parse the header from the provided data
        hdr = sam_hdr_parse(size, (const char *)data);
        if (hdr == NULL) {
            // Parsing failed, return early
            return 0;
        }
    } else {
        // No data to parse, return early
        return 0;
    }

    // Ensure hdr is not NULL
    if (hdr != NULL) {
        // Call the function-under-test
        size_t length = sam_hdr_length(hdr);

        // Use the length in some way to avoid compiler optimizations
        printf("Header length: %zu\n", length);

        // Clean up
        sam_hdr_destroy(hdr);
    }

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

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
