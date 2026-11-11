// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hts_base_mod_state_alloc at sam_mods.c:191:21 in sam.h
// bam_parse_basemod2 at sam_mods.c:230:5 in sam.h
// bam_next_basemod at sam_mods.c:567:5 in sam.h
// bam_parse_basemod at sam_mods.c:449:5 in sam.h
// bam_mods_at_qpos at sam_mods.c:634:5 in sam.h
// bam_mods_at_next_pos at sam_mods.c:462:5 in sam.h
// bam_mods_recorded at sam_mods.c:655:6 in sam.h
// hts_base_mod_state_free at sam_mods.c:195:6 in sam.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sam.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(bam1_t)) {
        return 0;
    }

    // Prepare dummy file for BAM data
    write_dummy_file(Data, Size);

    // Initialize BAM alignment record
    bam1_t *b = (bam1_t *)malloc(sizeof(bam1_t));
    if (!b) return 0;
    memset(b, 0, sizeof(bam1_t));

    // Initialize modification state
    hts_base_mod_state *state = hts_base_mod_state_alloc();
    if (!state) {
        free(b);
        return 0;
    }

    // Initialize other required variables
    uint32_t flags = 0;
    hts_base_mod mods[10];
    int pos = 0;
    int n_mods = sizeof(mods) / sizeof(mods[0]);
    int ntype = 0;

    // Fuzz bam_parse_basemod2
    bam_parse_basemod2(b, state, flags);

    // Fuzz bam_next_basemod
    bam_next_basemod(b, state, mods, n_mods, &pos);

    // Fuzz bam_parse_basemod
    bam_parse_basemod(b, state);

    // Fuzz bam_mods_at_qpos
    bam_mods_at_qpos(b, pos, state, mods, n_mods);

    // Fuzz bam_mods_at_next_pos
    bam_mods_at_next_pos(b, state, mods, n_mods);

    // Fuzz bam_mods_recorded
    int *mod_types = bam_mods_recorded(state, &ntype);

    // Cleanup
    hts_base_mod_state_free(state);
    free(b);

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
