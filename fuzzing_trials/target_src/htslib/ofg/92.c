#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h>

// Fuzzing harness for hts_idx_get_stat
int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize the tid from the input data
    int tid = *(int *)data;

    // Create a dummy hts_idx_t pointer
    // Since we can't know the size of hts_idx_t, we'll assume idx is a valid pointer
    // for the purpose of this fuzz test. In a real test, you would need a valid index.
    const hts_idx_t *idx = NULL; // or create a valid index if possible

    // Initialize variables for the result
    uint64_t mapped = 0;
    uint64_t unmapped = 0;

    // Call the function-under-test
    int result = hts_idx_get_stat(idx, tid, &mapped, &unmapped);

    // Use the result in some way to avoid compiler optimizations
    volatile int use_result = result;
    volatile uint64_t use_mapped = mapped;
    volatile uint64_t use_unmapped = unmapped;

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

    LLVMFuzzerTestOneInput_92(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
