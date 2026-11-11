#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our needs
    if (size < 7) {
        return 0;
    }

    // Initialize the parameters for H5Dcreate2
    hid_t loc_id = (hid_t)data[0]; // Use the first byte of data
    const char *name = "fuzz_dataset"; // A constant name for the dataset
    hid_t type_id = (hid_t)data[1]; // Use the second byte of data
    hid_t space_id = (hid_t)data[2]; // Use the third byte of data
    hid_t lcpl_id = (hid_t)data[3]; // Use the fourth byte of data
    hid_t dcpl_id = (hid_t)data[4]; // Use the fifth byte of data
    hid_t dapl_id = (hid_t)data[5]; // Use the sixth byte of data

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
