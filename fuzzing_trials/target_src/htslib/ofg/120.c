#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    // Initialize idx properly using htslib function with the correct number of arguments
    int n = 0; // Example value, adjust based on your specific use case
    int fmt = HTS_FMT_CSI;
    uint64_t offset0 = 0; // Example value, adjust based on your specific use case
    int min_shift = 14; // Example value, adjust based on your specific use case
    int n_lvls = 5; // Example value, adjust based on your specific use case
    
    hts_idx_t *idx = hts_idx_init(n, fmt, offset0, min_shift, n_lvls);
    uint64_t final_offset = 0;

    // Ensure idx is not NULL
    if (idx == NULL) {
        return 0; // Exit if initialization failed
    }

    // Use the first 8 bytes of data as the final_offset if size is sufficient
    if (size >= sizeof(uint64_t)) {
        final_offset = *(const uint64_t *)data;
    }

    // Call the function-under-test
    hts_idx_finish(idx, final_offset);

    // Destroy the index properly using htslib function
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

    LLVMFuzzerTestOneInput_120(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
