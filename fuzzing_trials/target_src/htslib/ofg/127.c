#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <htslib/sam.h>

// Dummy callback function for bam_plp_init
int dummy_callback_127(uint8_t *data, int len, void *user_data) {
    return 0;
}

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    bam_plp_t plp;
    bam1_t *b = bam_init1();

    // Initialize bam_plp_t with a dummy callback
    plp = bam_plp_init(dummy_callback_127, NULL);

    // Ensure the bam1_t structure is not NULL
    if (b == NULL || plp == NULL) {
        return 0;
    }

    // Ensure the bam1_t data buffer is large enough
    if (size > 0) {
        // Allocate memory for the data field in bam1_t
        b->data = malloc(size);
        if (b->data == NULL) {
            bam_destroy1(b);
            bam_plp_destroy(plp);
            return 0;
        }

        // Copy the input data into the bam1_t structure's data field
        memcpy(b->data, data, size);

        // Set the l_data to the size of the input data
        b->l_data = size;

        // Set up the core fields with some realistic values
        b->core.tid = 0;  // Assuming a single reference for simplicity
        b->core.pos = 0;  // Start at the beginning of the reference
        b->core.bin = hts_reg2bin(0, size, 0, 0);  // Calculate bin based on the data size
        b->core.qual = 20;  // Set a default mapping quality
        b->core.l_qname = 1;  // Minimal length for query name
        b->core.flag = 0;  // No special flags
        b->core.n_cigar = 1;  // Set a single CIGAR operation
        b->core.l_qseq = size;  // Set sequence length to size
        b->core.mtid = -1;  // No mate
        b->core.mpos = -1;  // No mate position
        b->core.isize = 0;  // No insert size

        // Set the data to some valid BAM content if possible
        if (size >= 1) {
            b->data[0] = 'A';  // Set a dummy base
        }
        if (size >= 4) {
            // Set a dummy CIGAR operation (e.g., 1M)
            b->data[1] = 0x40;  // Length of 1
            b->data[2] = 0x00;  // Operation is M (match)
            b->data[3] = 0x00;
        }
    }

    // Call the function-under-test
    int result = bam_plp_push(plp, b);

    // Clean up
    // Do not manually free(b->data) as bam_destroy1 will handle it
    bam_destroy1(b);
    bam_plp_destroy(plp);

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

    LLVMFuzzerTestOneInput_127(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
