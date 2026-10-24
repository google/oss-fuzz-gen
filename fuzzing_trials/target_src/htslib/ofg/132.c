#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract all parameters
    if (size < sizeof(int) * 4 + sizeof(uint64_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int param1 = *(const int *)(data);
    int param2 = *(const int *)(data + sizeof(int));
    uint64_t param3 = *(const uint64_t *)(data + sizeof(int) * 2);
    int param4 = *(const int *)(data + sizeof(int) * 2 + sizeof(uint64_t));
    int param5 = *(const int *)(data + sizeof(int) * 3 + sizeof(uint64_t));

    // Call the function-under-test
    hts_idx_t *index = hts_idx_init(param1, param2, param3, param4, param5);

    // Clean up if the function returns a non-null pointer
    if (index != NULL) {
        hts_idx_destroy(index);
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

    LLVMFuzzerTestOneInput_132(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
