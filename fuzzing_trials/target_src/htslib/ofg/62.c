#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>

// Function to ensure the input data is not null and has a minimum size
static int is_valid_input(const uint8_t *data, size_t size) {
    return data != NULL && size > 0;
}

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    if (!is_valid_input(data, size)) {
        return 0; // Return early if input is invalid
    }

    // Initialize an index with a plausible sequence length (e.g., 1000)
    hts_idx_t *index = hts_idx_init(1000, HTS_FMT_CSI, 0, 0, 0);
    if (index == NULL) {
        return 0; // Return if index initialization fails
    }

    uint32_t meta_type = 1; // Example meta type, can vary based on use case
    uint8_t *meta_data = NULL;
    int meta_length = (int)size; // Use the entire size of the input data

    // Allocate memory for meta_data and ensure allocation is successful
    meta_data = (uint8_t *)malloc(meta_length);
    if (meta_data == NULL) {
        hts_idx_destroy(index);
        return 0;
    }

    // Copy the input data to meta_data
    memcpy(meta_data, data, meta_length);

    // Modify the meta_data to ensure it's non-trivial and affects the function
    for (int i = 0; i < meta_length; i++) {
        meta_data[i] ^= 0xAA; // Example modification to make the data non-trivial
    }

    // Call the function-under-test with valid input
    hts_idx_set_meta(index, meta_type, meta_data, meta_length);

    // Cleanup
    free(meta_data);
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

    LLVMFuzzerTestOneInput_62(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
