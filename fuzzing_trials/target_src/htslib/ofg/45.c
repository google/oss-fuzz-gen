#include <stdint.h>
#include <stdlib.h>
#include <htslib/sam.h>
#include <htslib/hts.h>
#include <string.h>

// Define a callback function for bam_plp_init
int dummy_callback_45(void *data, bam1_t *b) {
    if (data == NULL || b == NULL) {
        return -1; // Return -1 to indicate no more reads
    }

    // Copy data into bam1_t structure
    bam1_t *input_bam = (bam1_t *)data;
    memcpy(b, input_bam, sizeof(bam1_t));

    // Indicate that a read has been processed
    return 1;
}

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    if (size < sizeof(bam1_t)) {
        return 0; // Not enough data to form a bam1_t structure
    }

    // Create a bam1_t object from input data
    bam1_t input_bam;
    memcpy(&input_bam, data, sizeof(bam1_t));

    bam_plp_t plp;
    int tid = 0;
    hts_pos_t pos = 0;
    int n_plp = 0;

    // Initialize bam_plp_t with the dummy_callback_45 function and the input_bam
    plp = bam_plp_init(dummy_callback_45, &input_bam);

    if (plp == NULL) {
        return 0;
    }

    // Fuzz the bam_plp64_auto function
    const bam_pileup1_t *pileup = bam_plp64_auto(plp, &tid, &pos, &n_plp);

    // Clean up
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

    LLVMFuzzerTestOneInput_45(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
