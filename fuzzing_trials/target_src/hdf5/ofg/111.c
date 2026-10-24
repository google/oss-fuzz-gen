#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < 6) {
        return 0;
    }

    // Initialize the parameters for H5Adelete_by_idx
    hid_t loc_id = (hid_t)data[0];  // Using the first byte as loc_id
    const char *name = "test_attribute";  // A valid attribute name
    H5_index_t idx_type = (H5_index_t)(data[1] % 3);  // Based on H5_index_t enum
    H5_iter_order_t order = (H5_iter_order_t)(data[2] % 3);  // Based on H5_iter_order_t enum
    hsize_t n = (hsize_t)data[3];  // Using the third byte as n
    hid_t lapl_id = (hid_t)data[4];  // Using the fourth byte as lapl_id

    // Call the function-under-test
    herr_t result = H5Adelete_by_idx(loc_id, name, idx_type, order, n, lapl_id);

    // Return 0 as required by the fuzzer
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

    LLVMFuzzerTestOneInput_111(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
