#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h>
#include <htslib/tbx.h>

// Initialize hts_idx_t with appropriate parameters
hts_idx_t *hts_idx_init(int n, int fmt, uint64_t offset0, int min_shift, int n_lvls);

int LLVMFuzzerTestOneInput_214(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(uint64_t) + sizeof(int) * 2) {
        return 0;
    }

    // Extract parameters from the input data
    int n = *(int *)data;
    int fmt = *(int *)(data + sizeof(int));
    uint64_t offset0 = *(uint64_t *)(data + 2 * sizeof(int));
    int min_shift = *(int *)(data + 2 * sizeof(int) + sizeof(uint64_t));
    int n_lvls = *(int *)(data + 2 * sizeof(int) + sizeof(uint64_t) + sizeof(int));

    // Initialize a hts_idx_t structure using the extracted parameters
    hts_idx_t *index = hts_idx_init(n, fmt, offset0, min_shift, n_lvls);
    if (index == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = hts_idx_fmt(index);

    // Clean up
    hts_idx_destroy(index);

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

    LLVMFuzzerTestOneInput_214(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
