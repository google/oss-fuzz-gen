#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "htslib/sam.h"
#include "htslib/hts.h"

// A dummy callback function for bam_mplp_init
static int read_bam(void *data, bam1_t *b) {
    return -1; // Return -1 to indicate no more data
}

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Check if the size is sufficient for our needs
    if (size < sizeof(bam_hdr_t)) {
        return 0;
    }

    // Initialize a BAM file header
    bam_hdr_t *header = bam_hdr_init();
    if (!header) {
        fprintf(stderr, "Failed to initialize BAM header\n");
        return 0;
    }

    // Simulate a valid input for bam_mplp_init by creating a dummy bam1_t object
    bam1_t *b = bam_init1();
    if (!b) {
        bam_hdr_destroy(header);
        fprintf(stderr, "Failed to initialize BAM record\n");
        return 0;
    }

    // Initialize a BAM multi-pileup iterator with a dummy callback
    bam_mplp_t mplp = bam_mplp_init(1, read_bam, b);
    if (!mplp) {
        bam_destroy1(b);
        bam_hdr_destroy(header);
        fprintf(stderr, "Failed to initialize BAM multi-pileup\n");
        return 0;
    }

    int ref_id = 0;
    int pos = 0;
    int n_plp = 0;
    const bam_pileup1_t *plp = NULL;

    // Simulate a valid input for bam_mplp_auto
    int result = bam_mplp_auto(mplp, &ref_id, &pos, &n_plp, &plp);

    // Output the result for debugging purposes (optional)
    printf("Result: %d, Ref ID: %d, Pos: %d, N plp: %d\n", result, ref_id, pos, n_plp);

    // Clean up
    bam_mplp_destroy(mplp);
    bam_destroy1(b);
    bam_hdr_destroy(header);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
