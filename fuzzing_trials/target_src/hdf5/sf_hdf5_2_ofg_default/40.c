#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Define and initialize variables for the function parameters
    hid_t loc_id = H5P_DEFAULT; // Using default property list ID
    char name[256]; // Buffer for the dataset name
    hid_t type_id = H5T_NATIVE_INT; // Using native integer type
    hid_t space_id = H5S_ALL; // Using all available space
    hid_t lcpl_id = H5P_DEFAULT; // Using default link creation property list
    hid_t dcpl_id = H5P_DEFAULT; // Using default dataset creation property list
    hid_t dapl_id = H5P_DEFAULT; // Using default dataset access property list

    // Ensure data is not empty and size is sufficient for the name
    if (size > 0 && size < sizeof(name)) {
        // Copy data to name buffer ensuring null termination
        memcpy(name, data, size);
        name[size] = '\0'; // Null-terminate the string

        // Call the function-under-test
        hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

        // Close the dataset if it was successfully created
        if (dataset_id >= 0) {
            H5Dclose(dataset_id);
        }
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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
