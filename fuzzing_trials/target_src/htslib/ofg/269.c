#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h>

// Remove 'extern "C"' as it is not needed in C code
int LLVMFuzzerTestOneInput_269(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    hts_idx_t *idx = hts_idx_init(0, HTS_FMT_CSI, 0, 0, 0); // Initialize index with dummy values
    int tid = 0; // Thread ID
    hts_pos_t beg = 0; // Beginning position
    hts_pos_t end = 0; // Ending position
    uint64_t offset = 0; // Offset
    int is_mapped = 1; // Is mapped flag

    if (size >= sizeof(int) + 2 * sizeof(hts_pos_t) + sizeof(uint64_t) + sizeof(int)) {
        // Extract values from the input data if the size is sufficient
        tid = *(int *)data;
        beg = *(hts_pos_t *)(data + sizeof(int));
        end = *(hts_pos_t *)(data + sizeof(int) + sizeof(hts_pos_t));
        offset = *(uint64_t *)(data + sizeof(int) + 2 * sizeof(hts_pos_t));
        is_mapped = *(int *)(data + sizeof(int) + 2 * sizeof(hts_pos_t) + sizeof(uint64_t));
    }

    // Call the function-under-test
    hts_idx_push(idx, tid, beg, end, offset, is_mapped);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_269(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
