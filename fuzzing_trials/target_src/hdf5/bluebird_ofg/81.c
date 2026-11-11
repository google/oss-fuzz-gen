#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include "hdf5.h"

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Ensure there is enough data for all parameters
    if (size < sizeof(hid_t) * 2 + sizeof(H5_index_t) + sizeof(H5_iter_order_t) + sizeof(hsize_t) + 1) {
        return 0;
    }

    // Extract parameters from the data
    size_t offset = 0;

    hid_t loc_id = *(const hid_t *)(data + offset);
    offset += sizeof(hid_t);

    // Ensure the name is null-terminated
    size_t name_len = size - offset - sizeof(H5_index_t) - sizeof(H5_iter_order_t) - sizeof(hsize_t) - sizeof(hid_t);
    if (name_len <= 0) {
        return 0;
    }
    char *name = (char *)malloc(name_len + 1);
    if (!name) {
        return 0;
    }
    memcpy(name, data + offset, name_len);
    name[name_len] = '\0';
    offset += name_len;

    H5_index_t idx_type = *(const H5_index_t *)(data + offset);
    offset += sizeof(H5_index_t);

    H5_iter_order_t order = *(const H5_iter_order_t *)(data + offset);
    offset += sizeof(H5_iter_order_t);

    hsize_t n = *(const hsize_t *)(data + offset);
    offset += sizeof(hsize_t);

    hid_t lapl_id = *(const hid_t *)(data + offset);
    offset += sizeof(hid_t);

    // Call the function-under-test
    H5Adelete_by_idx(loc_id, name, idx_type, order, n, lapl_id);

    // Free allocated memory
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
