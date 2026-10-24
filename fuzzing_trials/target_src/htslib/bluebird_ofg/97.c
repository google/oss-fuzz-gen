#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h"
#include "htslib/hts.h"

// Function signature for the function-under-test
int bam_mods_at_next_pos(const bam1_t *b, hts_base_mod_state *state, hts_base_mod *mod, int flag);

int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    bam1_t *b = bam_init1();
    hts_base_mod_state *state = hts_base_mod_state_alloc();
    hts_base_mod mod;
    int flag = 0;

    // Ensure that the input data is large enough to be used for bam1_t
    if (size < sizeof(bam1_t) + 4) { // Ensure there's enough data for initialization
        bam_destroy1(b);
        hts_base_mod_state_free(state);
        return 0;
    }

    // Initialize bam1_t structure with valid data
    b->core.tid = 0;
    b->core.pos = 0;
    b->core.bin = 0;
    b->core.qual = 0;
    b->core.l_qname = 1;
    b->core.flag = 0;
    b->core.n_cigar = 0;
    b->core.l_qseq = 1;
    b->core.mtid = 0;
    b->core.mpos = 0;
    b->core.isize = 0;

    // Properly initialize m_data to a sensible default
    b->m_data = size;

    // Allocate memory for b->data based on m_data
    b->l_data = size < b->m_data ? size : b->m_data;
    b->data = (uint8_t *)malloc(b->l_data);
    if (!b->data) {
        bam_destroy1(b);
        hts_base_mod_state_free(state);
        return 0;
    }

    // Copy data into bam1_t structure
    memcpy(b->data, data, b->l_data);

    // Adjust the core.l_qseq and core.n_cigar to ensure meaningful data
    b->core.l_qseq = b->l_data > 0 ? b->l_data : 1;
    b->core.n_cigar = b->l_data > 0 ? 1 : 0;

    // Call the function-under-test
    int result = bam_mods_at_next_pos(b, state, &mod, flag);

    // Clean up
    if (b->data) {
        free(b->data);
        b->data = NULL; // Avoid double-free by nullifying the pointer after freeing
    }
    bam_destroy1(b);
    hts_base_mod_state_free(state);

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

    LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
