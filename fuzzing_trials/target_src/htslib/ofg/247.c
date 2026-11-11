#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> // Include string.h for memcpy
#include <htslib/hts.h>
#include <htslib/hts_defs.h>
#include <htslib/sam.h> // Include for hts_idx_t and related functions

int LLVMFuzzerTestOneInput_247(const uint8_t *data, size_t size) {
    // Check if size is enough to proceed with meaningful data
    if (size < sizeof(int)) {
        return 0;
    }

    // Allocate memory for hts_idx_t using a valid function
    hts_idx_t *idx = hts_idx_init(0, HTS_FMT_BAI, 0, 0, 0);
    if (!idx) {
        return 0;
    }

    // Dummy function for hts_id2name_f
    const char *dummy_name = "dummy_name";
    hts_id2name_f id2name_func = (hts_id2name_f)dummy_name;

    int num_seqs = 0;

    // Call the function-under-test
    const char **seqnames = hts_idx_seqnames(idx, &num_seqs, id2name_func, NULL);

    // Clean up
    hts_idx_destroy(idx);

    // If seqnames is not NULL, free the allocated memory
    if (seqnames) {
        for (int i = 0; i < num_seqs; i++) {
            free((void *)seqnames[i]);
        }
        free(seqnames);
    }

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

    LLVMFuzzerTestOneInput_247(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
