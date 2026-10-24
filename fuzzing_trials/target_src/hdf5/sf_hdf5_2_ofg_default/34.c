#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    hid_t loc_id = H5P_DEFAULT; // Use a default property list identifier
    const char *name = "dataset_name"; // A non-NULL name for the dataset
    hid_t type_id = H5T_NATIVE_INT; // Use a native integer type
    hid_t space_id = H5Screate(H5S_SCALAR); // Create a simple scalar dataspace
    hid_t lcpl_id = H5P_DEFAULT; // Use a default link creation property list
    hid_t dcpl_id = H5P_DEFAULT; // Use a default dataset creation property list
    hid_t dapl_id = H5P_DEFAULT; // Use a default dataset access property list

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close the dataspace if it was created
    if (space_id != H5I_INVALID_HID) {
        H5Sclose(space_id);
    }

    // Close the dataset if it was successfully created
    if (dataset_id != H5I_INVALID_HID) {
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
