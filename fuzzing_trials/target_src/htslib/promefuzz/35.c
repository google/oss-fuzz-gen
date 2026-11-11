// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hts_idx_load at hts.c:4973:12 in hts.h
// hts_idx_tbi_name at hts.c:2643:5 in hts.h
// hts_idx_save at hts.c:2820:5 in hts.h
// hts_idx_save_as at hts.c:2864:5 in hts.h
// hts_idx_destroy at hts.c:2682:6 in hts.h
// hts_idx_load3 at hts.c:4982:12 in hts.h
// hts_idx_destroy at hts.c:2682:6 in hts.h
// sam_index_build at sam.c:1076:5 in sam.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hts.h"
#include "sam.h"

static void write_dummy_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare dummy file
    const char *dummy_filename = "./dummy_file";
    write_dummy_file(dummy_filename, Data, Size);

    // Fuzz hts_idx_load
    hts_idx_t *idx = hts_idx_load(dummy_filename, HTS_FMT_BAI);
    if (idx) {
        // Fuzz hts_idx_tbi_name
        int tid = Data[0] % 256; // Use first byte as tid
        const char *name = (Size > 1) ? (const char *)&Data[1] : "default_name";
        hts_idx_tbi_name(idx, tid, name);

        // Fuzz hts_idx_save
        hts_idx_save(idx, dummy_filename, HTS_FMT_BAI);

        // Fuzz hts_idx_save_as
        hts_idx_save_as(idx, dummy_filename, NULL, HTS_FMT_BAI);

        // Clean up
        hts_idx_destroy(idx);
    }

    // Fuzz hts_idx_load3
    idx = hts_idx_load3(dummy_filename, NULL, HTS_FMT_CSI, HTS_IDX_SAVE_REMOTE);
    if (idx) {
        // Clean up
        hts_idx_destroy(idx);
    }

    // Fuzz sam_index_build
    sam_index_build(dummy_filename, 0);

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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
