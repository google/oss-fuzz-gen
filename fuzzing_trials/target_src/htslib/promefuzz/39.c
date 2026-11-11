// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// bam_mods_query_type at sam_mods.c:667:5 in sam.h
// bam_mods_queryi at sam_mods.c:692:5 in sam.h
// bam_mods_recorded at sam_mods.c:655:6 in sam.h
// bam_parse_basemod at sam_mods.c:449:5 in sam.h
// bam_next_basemod at sam_mods.c:567:5 in sam.h
// bam_mods_at_qpos at sam_mods.c:634:5 in sam.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sam.h>

#define MAX_BASE_MOD 10

static bam1_t* create_dummy_bam_record() {
    bam1_t* b = (bam1_t*)malloc(sizeof(bam1_t));
    if (!b) return NULL;

    b->core.pos = 0;
    b->core.tid = 0;
    b->core.bin = 0;
    b->core.qual = 255;
    b->core.l_extranul = 0;
    b->core.flag = 0;
    b->core.l_qname = 0;
    b->core.n_cigar = 0;
    b->core.l_qseq = 0;
    b->core.mtid = 0;
    b->core.mpos = 0;
    b->core.isize = 0;
    b->id = 0;
    b->data = NULL;
    b->l_data = 0;
    b->m_data = 0;
    b->mempolicy = 0;

    return b;
}

static void free_dummy_bam_record(bam1_t* b) {
    if (b) {
        free(b->data);
        free(b);
    }
}

int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(bam1_t)) return 0;

    bam1_t* bam_record = create_dummy_bam_record();
    if (!bam_record) return 0;

    hts_base_mod_state* mod_state = hts_base_mod_state_alloc();
    if (!mod_state) {
        free_dummy_bam_record(bam_record);
        return 0;
    }

    hts_base_mod mods[MAX_BASE_MOD];
    int pos = 0;

    // Fuzz bam_next_basemod
    int mod_count = bam_next_basemod(bam_record, mod_state, mods, MAX_BASE_MOD, &pos);
    if (mod_count < 0) {
        // Handle error if needed
    }

    // Fuzz bam_mods_query_type
    int strand = 0, implicit = 0;
    char canonical = 0;
    int code = Data[0] % 256; // Use the first byte as a code
    int query_result = bam_mods_query_type(mod_state, code, &strand, &implicit, &canonical);
    if (query_result < 0) {
        // Handle error if needed
    }

    // Fuzz bam_parse_basemod
    int parse_result = bam_parse_basemod(bam_record, mod_state);
    if (parse_result < 0) {
        // Handle error if needed
    }

    // Fuzz bam_mods_at_qpos
    int qpos = 0;
    int at_qpos_count = bam_mods_at_qpos(bam_record, qpos, mod_state, mods, MAX_BASE_MOD);
    if (at_qpos_count < 0) {
        // Handle error if needed
    }

    // Fuzz bam_mods_recorded
    int ntype = 0;
    int* recorded_mods = bam_mods_recorded(mod_state, &ntype);
    if (!recorded_mods) {
        // Handle error if needed
    }

    // Fuzz bam_mods_queryi
    int query_index_result = bam_mods_queryi(mod_state, 0, &strand, &implicit, &canonical);
    if (query_index_result < 0) {
        // Handle error if needed
    }

    hts_base_mod_state_free(mod_state);
    free_dummy_bam_record(bam_record);

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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
