#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h"

int LLVMFuzzerTestOneInput_189(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Not enough data to form an integer
    }

    // Initialize a sam_hdr_t object
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0; // Failed to initialize header
    }

    // Create a fake header text to populate the sam_hdr_t
    const char *header_text = "@HD\tVN:1.0\n@SQ\tSN:chr1\tLN:248956422\n";
    if (sam_hdr_add_lines(hdr, header_text, strlen(header_text)) < 0) {
        sam_hdr_destroy(hdr);
        return 0; // Failed to add lines to header
    }

    // Extract an integer from the input data
    int tid = *(const int *)data;

    // Call the function-under-test
    const char *result = sam_hdr_tid2name(hdr, tid);

    // Print the result (for debugging purposes)
    if (result != NULL) {
        printf("Result: %s\n", result);
    }

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

    LLVMFuzzerTestOneInput_189(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
