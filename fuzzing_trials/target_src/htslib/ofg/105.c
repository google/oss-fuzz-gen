#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <htslib/sam.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract meaningful values
    if (size < sizeof(hts_pos_t) * 2 + sizeof(int) + sizeof(uint64_t) + sizeof(int) * 2) {
        return 0;
    }

    // Extract parameters from the input data
    int tid = *((int *)data);
    hts_pos_t beg = *((hts_pos_t *)(data + sizeof(int)));
    hts_pos_t end = *((hts_pos_t *)(data + sizeof(int) + sizeof(hts_pos_t)));
    uint64_t offset0 = *((uint64_t *)(data + sizeof(int) + sizeof(hts_pos_t) * 2));
    int min_shift = *((int *)(data + sizeof(int) + sizeof(hts_pos_t) * 2 + sizeof(uint64_t)));
    int n_lvls = *((int *)(data + sizeof(int) + sizeof(hts_pos_t) * 2 + sizeof(uint64_t) + sizeof(int)));

    // Initialize hts_idx_t with the extracted parameters
    hts_idx_t *idx = hts_idx_init(0, HTS_FMT_CSI, offset0, min_shift, n_lvls);

    // Call the function-under-test
    hts_itr_t *itr = sam_itr_queryi(idx, tid, beg, end);

    // Clean up
    if (itr != NULL) {
        hts_itr_destroy(itr);
    }
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_105(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
