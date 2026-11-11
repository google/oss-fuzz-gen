#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/hts.h"
#include "/src/htslib/htslib/tbx.h"
#include "/src/htslib/htslib/hts_defs.h"
#include "/src/htslib/htslib/hts_log.h" // Include for logging if necessary
#include "/src/htslib/htslib/bgzf.h"    // Include for BGZF related operations

int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Determine a reasonable size for the data
    const size_t idx_size = 100; // Arbitrary size, as we can't use sizeof(hts_idx_t)

    if (size < idx_size) {
        return 0;
    }

    // Initialize the hts_idx_t structure with dummy values
    int n = 1; // Number of reference sequences
    int fmt = HTS_FMT_CSI; // Format, using a constant from the library
    uint64_t offset0 = 0; // Initial offset
    int min_shift = 14; // Minimum shift
    int n_lvls = 5; // Number of levels

    hts_idx_t *idx = hts_idx_init(n, fmt, offset0, min_shift, n_lvls);
    if (idx == NULL) {
        return 0;
    }

    // Ensure the rest of the data is available for the other parameters
    if (size < idx_size + sizeof(int) + 2 * sizeof(uint64_t)) {
        hts_idx_destroy(idx);
        return 0;
    }

    // Extract an integer from the input data
    int tid = *((int *)(data + idx_size));

    // Prepare uint64_t variables for the function call
    uint64_t mapped = 0;
    uint64_t unmapped = 0;

    // Ensure tid is within a valid range
    if (tid < 0 || tid >= n) {
        hts_idx_destroy(idx);
        return 0;
    }

    // Call the function-under-test
    hts_idx_get_stat(idx, tid, &mapped, &unmapped);

    // Clean up
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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
