#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_237(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Ensure there is enough data for a valid operation
    if (size < 3) return 0;

    // Use the first byte as a file identifier
    hid_t file_id = (hid_t)data[0];

    // Use the second byte as a dataset identifier
    hid_t dapl_id = (hid_t)data[1];

    // Ensure the remaining data is null-terminated for the dataset name
    char dataset_name[256];
    size_t name_size = size - 2;
    if (name_size > 255) name_size = 255;
    for (size_t i = 0; i < name_size; i++) {
        dataset_name[i] = (char)data[i + 2];
    }
    dataset_name[name_size] = '\0';

    // Call the function-under-test
    hid_t dataset_id = H5Dopen2(file_id, dataset_name, dapl_id);

    // Close the dataset if it was successfully opened
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    // Close the HDF5 library
    H5close();

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

    LLVMFuzzerTestOneInput_237(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
