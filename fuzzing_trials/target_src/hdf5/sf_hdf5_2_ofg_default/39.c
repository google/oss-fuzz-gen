#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Initialize variables
    hid_t loc_id = H5P_DEFAULT;  // Default property list
    hid_t type_id = H5T_NATIVE_INT;  // Native integer type
    hid_t space_id = H5S_SCALAR;  // Scalar dataspace
    hid_t lcpl_id = H5P_DEFAULT;  // Link creation property list
    hid_t dcpl_id = H5P_DEFAULT;  // Dataset creation property list
    hid_t dapl_id = H5P_DEFAULT;  // Dataset access property list

    // Ensure the data is not empty and has a valid size
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char name[256];
    size_t name_len = size < 255 ? size : 255;
    for (size_t i = 0; i < name_len; i++) {
        name[i] = data[i];
    }
    name[name_len] = '\0';

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close the dataset if it was created successfully
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
