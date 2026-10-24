#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include "htslib/sam.h"
#include "htslib/hts.h"
#include "/src/htslib/htslib/hts_expr.h" // Include for hts_filter_t and related functions

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    sam_hdr_t *header = NULL;
    bam1_t *alignment = NULL;
    hts_filter_t *filter = NULL;
    int result;

    // Initialize the header with a dummy header text
    const char *header_text = "@HD\tVN:1.0\n";
    header = sam_hdr_parse(strlen(header_text), header_text);
    if (header == NULL) {
        return 0;
    }

    // Initialize the alignment
    alignment = bam_init1();
    if (alignment == NULL) {
        sam_hdr_destroy(header);
        return 0;
    }

    // Initialize the filter with a dummy expression (e.g., "1")
    filter = hts_filter_init("1");
    if (filter == NULL) {
        sam_hdr_destroy(header);
        bam_destroy1(alignment);
        return 0;
    }

    // Ensure the data size is sufficient for setting up the alignment
    if (size > 4) { // Ensure there's enough data for meaningful processing
        // Assuming data is in the correct format for bam1_t
        bam1_core_t *core = &alignment->core;
        core->l_qname = data[0] % 255 + 1;  // Set a valid qname length
        core->flag = data[1]; // Set some flags
        core->n_cigar = data[2] % 10; // Set a reasonable number of CIGAR operations
        core->l_qseq = data[3] % 100; // Set a reasonable sequence length

        alignment->l_data = size - 4;
        alignment->data = (uint8_t *)malloc(alignment->l_data);
        if (alignment->data == NULL) {
            sam_hdr_destroy(header);
            bam_destroy1(alignment);
            hts_filter_free(filter);
            return 0;
        }
        memcpy(alignment->data, data + 4, alignment->l_data);
    } else {
        // If size is too small, we cannot proceed with meaningful fuzzing
        sam_hdr_destroy(header);
        bam_destroy1(alignment);
        hts_filter_free(filter);
        return 0;
    }

    // Call the function-under-test
    result = sam_passes_filter(header, alignment, filter);

    // Clean up
    sam_hdr_destroy(header);
    bam_destroy1(alignment);
    hts_filter_free(filter);

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
