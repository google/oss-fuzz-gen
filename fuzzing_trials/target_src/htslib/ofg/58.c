#include <stdint.h>
#include <stdlib.h>
#include <htslib/sam.h>
#include <htslib/hts.h>
#include <htslib/bgzf.h> // Include this for BGZF-related functions

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Initialize necessary structures
    // Instead of allocating memory for hts_idx_t, we should use a function that returns an index
    BGZF *bgzf = bgzf_open("-", "r"); // Open a BGZF stream for reading
    hts_idx_t *index = hts_idx_load("-", HTS_FMT_BAI); // Load an index
    sam_hdr_t *header = sam_hdr_init();
    hts_reglist_t *reglist = (hts_reglist_t *)malloc(sizeof(hts_reglist_t));
    unsigned int flags = 0;

    // Ensure the data is not empty and large enough for meaningful fuzzing
    if (size < sizeof(hts_reglist_t)) {
        if (index != NULL) hts_idx_destroy(index);
        free(reglist);
        sam_hdr_destroy(header);
        bgzf_close(bgzf);
        return 0;
    }

    // Assign some values to the reglist structure from the input data
    reglist->reg = (char *)data;
    reglist->count = 1; // Set a non-zero count to avoid NULL issues

    // Fuzz the function-under-test
    hts_itr_t *itr = sam_itr_regions(index, header, reglist, flags);

    // Clean up
    if (itr != NULL) {
        hts_itr_destroy(itr);
    }
    if (index != NULL) hts_idx_destroy(index);
    free(reglist);
    sam_hdr_destroy(header);
    bgzf_close(bgzf);

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

    LLVMFuzzerTestOneInput_58(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
