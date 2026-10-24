#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t loc_id = H5P_DEFAULT; // Default property list
    char name[256]; // Buffer for the dataset name
    hid_t type_id = H5T_NATIVE_INT; // Default datatype
    hid_t space_id = H5S_SCALAR; // Default dataspace
    hid_t lcpl_id = H5P_DEFAULT; // Default link creation property list
    hid_t dcpl_id = H5P_DEFAULT; // Default dataset creation property list
    hid_t dapl_id = H5P_DEFAULT; // Default dataset access property list

    // Ensure the data size is sufficient for a name
    if (size < sizeof(name)) {
        return 0;
    }

    // Copy the data into the name buffer
    memcpy(name, data, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0'; // Null-terminate the string

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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
