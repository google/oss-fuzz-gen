#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract necessary parameters
    if (size < 7) {
        return 0;
    }

    // Extracting parameters from the data
    hid_t loc_id = (hid_t)data[0];
    hid_t type_id = (hid_t)data[1];
    hid_t space_id = (hid_t)data[2];
    hid_t lcpl_id = (hid_t)data[3];
    hid_t dcpl_id = (hid_t)data[4];
    hid_t dapl_id = (hid_t)data[5];

    // Ensure the dataset name is null-terminated and not empty
    size_t name_length = size - 6;
    if (name_length == 0) {
        return 0;
    }

    char *dataset_name = (char *)malloc(name_length + 1);
    if (dataset_name == NULL) {
        return 0;
    }
    memcpy(dataset_name, data + 6, name_length);
    dataset_name[name_length] = '\0';

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(loc_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up
    free(dataset_name);

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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
