#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <htslib/hts.h>
#include <htslib/sam.h>
#include <htslib/cram.h>  // Include this for CRAM specific functions
#include <string.h>       // Include this for memcpy

int LLVMFuzzerTestOneInput_205(const uint8_t *data, size_t size) {
    // Create a memory buffer from the input data
    htsFile *file = hts_open_format("mem:", "rc", NULL);  // Use "rc" for read CRAM
    if (!file) return 0;

    // Create a temporary buffer to hold the data
    char *buffer = (char *)malloc(size);
    if (!buffer) {
        hts_close(file);
        return 0;
    }
    memcpy(buffer, data, size);

    // Write input data to the htsFile buffer
    if (hts_set_opt(file, CRAM_OPT_DECODE_MD, 0) < 0) {
        free(buffer);
        hts_close(file);
        return 0;
    }

    // Initialize the hts_idx_t and hts_itr_t structures
    hts_idx_t *idx = hts_idx_load(file->fn, HTS_FMT_CRAI);
    if (!idx) {
        free(buffer);
        hts_close(file);
        return 0;
    }

    hts_itr_t *itr = hts_itr_query(idx, 0, 0, 0, 0);
    if (!itr) {
        hts_idx_destroy(idx);
        free(buffer);
        hts_close(file);
        return 0;
    }

    // Call the function-under-test
    hts_itr_multi_cram(idx, itr);

    // Clean up allocated memory
    hts_itr_destroy(itr);
    hts_idx_destroy(idx);
    free(buffer);
    hts_close(file);

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

    LLVMFuzzerTestOneInput_205(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
