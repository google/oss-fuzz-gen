// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hts_idx_init at hts.c:2400:12 in hts.h
// hts_idx_fmt at hts.c:2709:5 in hts.h
// hts_idx_nseq at hts.c:3105:5 in hts.h
// hts_idx_get_stat at hts.c:3110:5 in hts.h
// hts_idx_push at hts.c:2553:5 in hts.h
// hts_itr_multi_bam at hts.c:3597:5 in hts.h
// hts_idx_destroy at hts.c:2682:6 in hts.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hts.h"

static void write_dummy_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 5 + sizeof(uint64_t)) {
        return 0;
    }

    const int *int_data = (const int *)Data;
    const uint64_t *offset_data = (const uint64_t *)(Data + sizeof(int) * 5);

    int n = int_data[0];
    int fmt = int_data[1];
    uint64_t offset0 = *offset_data;
    int min_shift = int_data[2];
    int n_lvls = int_data[3];
    int tid = int_data[4];

    if (n < 0 || fmt < 0 || min_shift < 0 || n_lvls < 0 || tid < 0) {
        return 0;
    }

    hts_idx_t *idx = hts_idx_init(n, fmt, offset0, min_shift, n_lvls);
    if (!idx) {
        return 0;
    }

    int fmt_result = hts_idx_fmt(idx);
    int nseq_result = hts_idx_nseq(idx);
    
    uint64_t mapped = 0, unmapped = 0;
    int stat_result = -1;
    if (tid < nseq_result) {
        stat_result = hts_idx_get_stat(idx, tid, &mapped, &unmapped);
    }

    hts_pos_t beg = 0, end = 1000;
    uint64_t offset = 0;
    int is_mapped = 1;
    int push_result = hts_idx_push(idx, tid, beg, end, offset, is_mapped);

    hts_itr_t iter = {0};
    iter.multi = 1;
    int multi_bam_result = hts_itr_multi_bam(idx, &iter);

    hts_idx_destroy(idx);

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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
