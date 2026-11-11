#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <htslib/sam.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Check if size is sufficient to create a meaningful header
    if (size < 4) return 0;

    // Initialize variables for the parameters
    hts_idx_t *idx = NULL; // Use NULL as a mock index since we can't allocate an incomplete type
    sam_hdr_t *hdr = sam_hdr_init(); // Initialize a SAM header

    // Create a mock header text
    char header_text[] = "@HD\tVN:1.6\n@SQ\tSN:chr1\tLN:1000\n";
    sam_hdr_add_lines(hdr, header_text, strlen(header_text));

    hts_reglist_t reglist; // Initialize a region list
    unsigned int flags = 0; // Example flag value

    // Ensure the region list is initialized with some values
    char region_name[] = "chr1"; // Example region name "chr1"
    reglist.reg = region_name; // Assign the region name directly as a const char*
    reglist.min_beg = 0; // Example minimum beginning
    reglist.max_end = 1000; // Example maximum end
    reglist.count = 1; // Example interval count
    reglist.intervals = (hts_pair_pos_t *)malloc(sizeof(hts_pair_pos_t));
    reglist.intervals[0].beg = 0; // Example interval beginning
    reglist.intervals[0].end = 1000; // Example interval end

    // Call the function-under-test
    hts_itr_t *itr = sam_itr_regions(idx, hdr, &reglist, flags);

    // Clean up
    if (itr) hts_itr_destroy(itr);
    sam_hdr_destroy(hdr);
    free(reglist.intervals);

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

    LLVMFuzzerTestOneInput_57(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
