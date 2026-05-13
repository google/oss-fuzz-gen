#include <stdint.h>
#include <stddef.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_233(const uint8_t *data, size_t size) {
    // Initialize a sam_hdr_t structure
    sam_hdr_t *header = sam_hdr_init();
    if (!header) {
        return 0;
    }

    // Add a dummy reference sequence to the header
    if (sam_hdr_add_line(header, "SQ", "SN:ref", "LN:1000", NULL) < 0) {
        sam_hdr_destroy(header);
        return 0;
    }

    // Ensure the size is non-zero to avoid division by zero or invalid access
    if (size == 0) {
        sam_hdr_destroy(header);
        return 0;
    }

    // Use the first byte of data to determine the index
    int tid = data[0] % sam_hdr_nref(header);

    // Call the function-under-test
    hts_pos_t length = sam_hdr_tid2len(header, tid);

    // Clean up
    sam_hdr_destroy(header);

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

    LLVMFuzzerTestOneInput_233(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
