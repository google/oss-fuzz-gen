#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_224(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    hid_t loc_id = 1; // Assuming a valid non-zero hid_t for location
    const char *obj_name = "test_object"; // A non-NULL object name
    H5_index_t idx_type = H5_INDEX_NAME; // A valid H5_index_t value
    H5_iter_order_t order = H5_ITER_INC; // A valid H5_iter_order_t value
    hsize_t n = 0; // An index position
    H5A_info_t ainfo; // Structure to hold the attribute information
    hid_t lapl_id = H5P_DEFAULT; // Default link access property list

    // Call the function-under-test
    herr_t result = H5Aget_info_by_idx(loc_id, obj_name, idx_type, order, n, &ainfo, lapl_id);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_224(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
