#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract required parameters
    if (size < sizeof(hid_t) + sizeof(H5_index_t) + sizeof(H5_iter_order_t) + sizeof(hsize_t) + sizeof(size_t)) {
        return 0;
    }

    // Initialize variables
    hid_t loc_id = *(const hid_t *)data;
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    const char *obj_name = "dummy_object_name"; // Use a dummy object name

    H5_index_t idx_type = *(const H5_index_t *)data;
    data += sizeof(H5_index_t);
    size -= sizeof(H5_index_t);

    H5_iter_order_t order = *(const H5_iter_order_t *)data;
    data += sizeof(H5_iter_order_t);
    size -= sizeof(H5_iter_order_t);

    hsize_t n = *(const hsize_t *)data;
    data += sizeof(hsize_t);
    size -= sizeof(hsize_t);

    size_t buf_size = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    char *name = (char *)malloc(buf_size); // Allocate buffer for the name using malloc

    if (name == NULL) {
        return 0; // If allocation fails, return 0
    }

    hid_t lapl_id = H5P_DEFAULT; // Use default link access property list

    // Call the function-under-test
    ssize_t result = H5Aget_name_by_idx(loc_id, obj_name, idx_type, order, n, name, buf_size, lapl_id);

    // Clean up
    free(name);

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

    LLVMFuzzerTestOneInput_167(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
