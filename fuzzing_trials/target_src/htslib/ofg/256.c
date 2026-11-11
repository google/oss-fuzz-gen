#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>
#include <htslib/hts.h>

extern int bam_mods_at_next_pos(const bam1_t *, hts_base_mod_state *, hts_base_mod *, int);

int LLVMFuzzerTestOneInput_256(const uint8_t *data, size_t size) {
    if (size < sizeof(bam1_t)) {
        return 0; // Not enough data to form a valid BAM record
    }

    bam1_t *bam_record = bam_init1();
    hts_base_mod_state *mod_state = hts_base_mod_state_alloc();
    hts_base_mod base_mod;
    int some_int = 1; // Arbitrary non-zero integer

    if (bam_record == NULL || mod_state == NULL) {
        bam_destroy1(bam_record);
        hts_base_mod_state_free(mod_state);
        return 0;
    }

    bam_record->data = (uint8_t *)malloc(size);
    if (bam_record->data != NULL) {
        memcpy(bam_record->data, data, size);
        bam_record->l_data = size;

        // Set bam_record core fields to simulate a valid BAM record
        bam_record->core.tid = 0; // Example tid
        bam_record->core.pos = 0; // Example position
        bam_record->core.qual = 30; // Example mapping quality
        bam_record->core.l_qname = 1; // Example query name length
        bam_record->core.flag = 0; // Example flag
        bam_record->core.n_cigar = 0; // Example number of CIGAR operations
        bam_record->core.l_qseq = 0; // Example query sequence length
        bam_record->core.mtid = -1; // Example mate tid
        bam_record->core.mpos = -1; // Example mate position
        bam_record->core.isize = 0; // Example insert size

        // Call the function-under-test
        bam_mods_at_next_pos(bam_record, mod_state, &base_mod, some_int);
    }

    // Clean up
    bam_destroy1(bam_record);
    hts_base_mod_state_free(mod_state);

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

    LLVMFuzzerTestOneInput_256(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
