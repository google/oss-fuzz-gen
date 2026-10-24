#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "htslib/sam.h"
#include "htslib/hts.h"

// Function signature for bam_plp_next
const bam_pileup1_t * bam_plp_next(bam_plp_t, int *, int *, int *);

// Fuzzer entry point
int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Initialize variables
    bam_plp_t plp;
    int tid = 0;
    int pos = 0;
    int n_plp = 0;
    const bam_pileup1_t *pileup = NULL;

    // Check if the input size is sufficient to create a bam1_t structure
    if (size < sizeof(bam1_t)) {
        return 0; // Not enough data to proceed
    }

    // Create a dummy bam1_t object
    bam1_t *b = bam_init1();
    if (!b) {
        return 0; // Failed to allocate memory
    }

    // Ensure that the data buffer is large enough
    if (b->m_data < size) {
        b->m_data = size;
        b->data = realloc(b->data, b->m_data);
        if (!b->data) {
            bam_destroy1(b);
            return 0; // Memory allocation failed
        }
    }

    // Copy data into bam1_t structure
    memcpy(b->data, data, size);

    // Set core information to simulate a real BAM alignment
    b->core.tid = 0; // Set to a valid reference index
    b->core.pos = 0; // Set to a valid position
    b->core.l_qname = 1; // Set a minimal valid query name length
    b->core.l_qseq = 1; // Set a minimal valid sequence length
    b->core.flag = 0; // Set a valid flag
    b->core.n_cigar = 1; // Set a minimal valid CIGAR operations count

    // Create a dummy bam_plp_t object with a valid initialization
    plp = bam_plp_init(NULL, NULL);

    // Add the bam1_t object to the pileup
    bam_plp_push(plp, b);

    // Call the function-under-test
    while ((pileup = bam_plp_next(plp, &tid, &pos, &n_plp)) != NULL) {
        // Process the pileup
        for (int i = 0; i < n_plp; ++i) {
            // Access pileup[i] if needed
        }
    }

    // Clean up
    bam_plp_destroy(plp);
    bam_destroy1(b);

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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
