#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h>
#include <htslib/hts_defs.h> // Include necessary headers for hts_idx_t and related functions
#include "/src/htslib/hts_internal.h" // Correct path for the internal header

int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    if (size < 8) { // Ensure there's enough data to extract parameters
        return 0;
    }

    // Use the input data to derive parameters for hts_idx_init
    int param1 = data[0] % 2; // Example: use the first byte for the first int parameter
    int param2 = data[1] % 2; // Example: use the second byte for the second int parameter
    uint64_t param3 = 0;
    for (size_t i = 2; i < 6 && i < size; ++i) {
        param3 = (param3 << 8) | data[i]; // Use up to 4 bytes from data for param3
    }
    int param4 = data[6] % 2; // Use the seventh byte directly for the third int parameter
    int param5 = data[7] % 2; // Use the eighth byte directly for the fourth int parameter

    // Call the function-under-test
    hts_idx_t *idx = hts_idx_init(param1, param2, param3, param4, param5);

    // Clean up if necessary
    if (idx != NULL) {
        hts_idx_destroy(idx);
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

    LLVMFuzzerTestOneInput_131(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
