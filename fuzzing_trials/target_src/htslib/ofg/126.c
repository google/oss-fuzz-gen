#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated for string operations
    char *query = (char *)malloc(size + 1);
    if (query == NULL) {
        return 0;
    }
    memcpy(query, data, size);
    query[size] = '\0';

    // Dummy function pointers for the function signature
    hts_name2id_f name2id = NULL;
    void *hdr = NULL;
    hts_itr_query_func *query_func = NULL;
    hts_readrec_func *readrec_func = NULL;

    // Since we cannot create a valid hts_idx_t object directly, we pass NULL
    hts_idx_t *idx = NULL;

    // Call the function-under-test
    hts_itr_t *itr = hts_itr_querys(idx, query, name2id, hdr, query_func, readrec_func);

    // Cleanup
    if (itr != NULL) hts_itr_destroy(itr);
    free(query);

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

    LLVMFuzzerTestOneInput_126(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
