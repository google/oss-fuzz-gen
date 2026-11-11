#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>

// A mock function to create a bam_plp_t object
bam_plp_t create_bam_plp_128() {
    // In a real scenario, this would be a valid bam_plp_t object
    return NULL; // Adjusted to return NULL as we don't have a real implementation
}

// A mock function to create a bam1_t object
bam1_t* create_bam1() {
    // Allocate a bam1_t object and initialize it
    bam1_t *b = bam_init1();
    if (b != NULL) {
        // Initialize with some dummy data
        b->core.tid = 0;
        b->core.pos = 0;
        b->core.qual = 0;
        b->core.l_qname = 1;
        b->core.flag = 0;
        b->core.n_cigar = 0;
        b->core.l_qseq = 0;
        b->core.mtid = -1;
        b->core.mpos = -1;
        b->core.isize = 0;
    }
    return b;
}

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    if (size < sizeof(bam1_t)) {
        return 0; // Not enough data to fill a bam1_t structure
    }

    bam_plp_t plp = create_bam_plp_128();
    bam1_t *b = create_bam1();

    if (plp != NULL && b != NULL) {
        // Copy the fuzz data into the bam1_t data field
        memcpy(b->data, data, size < b->l_data ? size : b->l_data);

        // Call the function-under-test
        bam_plp_push(plp, b);

        // Clean up
        bam_destroy1(b);
        // Assuming plp should be freed if it was allocated
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

    LLVMFuzzerTestOneInput_128(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
