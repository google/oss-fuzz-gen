#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

herr_t dummy_operator_80(hid_t location_id, const char *attr_name, const H5A_info_t *ainfo, void *op_data) {
    // Dummy operator function for iteration
    return 0;
}

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    if (size < sizeof(hid_t) + sizeof(H5_index_t) + sizeof(H5_iter_order_t) + sizeof(hsize_t)) {
        return 0;
    }

    // Initialize variables
    hid_t loc_id = *(const hid_t *)data;
    data += sizeof(hid_t);

    H5_index_t idx_type = *(const H5_index_t *)data;
    data += sizeof(H5_index_t);

    H5_iter_order_t order = *(const H5_iter_order_t *)data;
    data += sizeof(H5_iter_order_t);

    hsize_t idx = *(const hsize_t *)data;
    data += sizeof(hsize_t);

    void *op_data = (void *)data;

    // Call the function-under-test
    H5Aiterate2(loc_id, idx_type, order, &idx, dummy_operator_80, op_data);

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

    LLVMFuzzerTestOneInput_80(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
