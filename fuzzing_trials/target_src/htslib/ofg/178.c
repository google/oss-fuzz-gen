#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy
#include <htslib/sam.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_178(const uint8_t *data, size_t size) {
    bam1_t *bam_record;
    hts_base_mod_state *mod_state;
    hts_base_mod mod;
    int qpos = 0;
    int max_mods = 1;
    int result;

    // Initialize bam_record
    bam_record = bam_init1();
    if (bam_record == NULL) {
        return 0;
    }

    // Initialize mod_state
    mod_state = hts_base_mod_state_alloc();
    if (mod_state == NULL) {
        bam_destroy1(bam_record);
        return 0;
    }

    // Simulate bam_record data
    if (size > 0) {
        bam_record->data = (uint8_t *)malloc(size);
        if (bam_record->data == NULL) {
            hts_base_mod_state_free(mod_state);
            bam_destroy1(bam_record);
            return 0;
        }
        memcpy(bam_record->data, data, size);
        bam_record->l_data = size;
    }

    // Call the function-under-test
    result = bam_mods_at_qpos(bam_record, qpos, mod_state, &mod, max_mods);

    // Clean up
    hts_base_mod_state_free(mod_state);
    bam_destroy1(bam_record);

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

    LLVMFuzzerTestOneInput_178(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
