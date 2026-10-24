#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <htslib/sam.h>

// Function to simulate a dummy callback for bam_plp_init
static int dummy_callback_11(void *data, bam1_t *b) {
    return -1; // Indicate no more data
}

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Check if the input data is large enough to be processed
    if (size < sizeof(bam1_t)) {
        return 0; // Not enough data to process
    }

    // Initialize a bam_plp_t object using the appropriate API
    bam_plp_t plp = bam_plp_init(dummy_callback_11, NULL); // Initialize with a dummy callback

    if (plp) {
        // Allocate a bam1_t object
        bam1_t *b = bam_init1();
        if (b) {
            // Ensure the bam1_t object has enough space for data
            if (b->m_data < size) {
                uint8_t *new_data = realloc(b->data, size);
                if (new_data) {
                    b->data = new_data;
                    b->m_data = size;
                } else {
                    bam_destroy1(b);
                    bam_plp_destroy(plp);
                    return 0; // Memory allocation failed
                }
            }

            // Copy data into bam1_t structure (ensure not to overrun)
            memcpy(b->data, data, size);

            // Set the core data length to the size of the input data
            b->l_data = size;

            // Set some fields in the bam1_t structure to simulate valid input
            b->core.tid = 0; // Example: set target ID
            b->core.pos = 0; // Example: set position
            b->core.bin = 0; // Example: set bin
            b->core.qual = 30; // Example: set mapping quality
            b->core.l_qname = 1; // Example: set length of query name
            b->core.flag = 0; // Example: set flag
            b->core.n_cigar = 0; // Example: set number of CIGAR operations
            b->core.l_qseq = 0; // Example: set length of query sequence
            b->core.mtid = -1; // Example: set mate target ID
            b->core.mpos = -1; // Example: set mate position
            b->core.isize = 0; // Example: set insert size

            // Push the bam1_t object to the pileup
            bam_plp_push(plp, b);

            // Call the function-under-test
            bam_plp_reset(plp);

            // Clean up
            bam_destroy1(b);
        }

        bam_plp_destroy(plp);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_11(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
