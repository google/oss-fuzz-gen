#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "htslib/hts.h"
#include "htslib/sam.h" // Include sam.h for hts_itr_querys and related types

// Dummy implementations for function pointers
int dummy_name2id(void *hdr, const char *name) {
    return 0; // Dummy implementation
}

// Define dummy implementations for the function pointers
int dummy_itr_query_func(hts_itr_t *iter, const char *reg, hts_idx_t *idx) {
    return 0; // Dummy implementation
}

int dummy_readrec_func(BGZF *fp, void *data, bam1_t *b, int *tid, int *beg, int *end) {
    return 0; // Dummy implementation
}

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for a string
    if (size < 1) {
        return 0;
    }

    // Allocate and copy data to a null-terminated string
    char *query_str = (char *)malloc(size + 1);
    if (!query_str) {
        return 0;
    }
    memcpy(query_str, data, size);
    query_str[size] = '\0';

    // Create a dummy hts_idx_t object
    // Since hts_idx_t is an incomplete type, we cannot directly allocate it.
    // Instead, we will use a dummy pointer for fuzzing purposes.
    hts_idx_t *dummy_idx = NULL;

    // Call the function-under-test
    hts_itr_t *itr = hts_itr_querys(dummy_idx, query_str, dummy_name2id, NULL, dummy_itr_query_func, dummy_readrec_func);

    // Clean up
    if (itr) {
        hts_itr_destroy(itr);
    }
    free(query_str);

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
