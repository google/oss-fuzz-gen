#include <stdint.h>
#include <hdf5.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    hid_t file_id, group_id;
    hsize_t index;
    H5G_obj_t obj_type;

    // Ensure there is enough data to extract necessary parameters
    if (size < sizeof(hsize_t)) {
        return 0;
    }

    // Create a new HDF5 file and group for testing
    file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    group_id = H5Gcreate(file_id, "/test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Extract index from data
    index = *((hsize_t*)data);

    // Call the function-under-test
    obj_type = H5Gget_objtype_by_idx(group_id, index);

    // Clean up
    H5Gclose(group_id);
    H5Fclose(file_id);

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
