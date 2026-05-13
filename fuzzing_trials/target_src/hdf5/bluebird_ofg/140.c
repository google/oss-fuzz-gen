#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract parameters
    if (size < 6 * sizeof(hid_t) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    hid_t loc_id = *(hid_t *)(data);
    const char *name = (const char *)(data + sizeof(hid_t));
    hid_t type_id = *(hid_t *)(data + sizeof(hid_t) + sizeof(char *));
    hid_t space_id = *(hid_t *)(data + 2 * sizeof(hid_t) + sizeof(char *));
    hid_t lcpl_id = *(hid_t *)(data + 3 * sizeof(hid_t) + sizeof(char *));
    hid_t dcpl_id = *(hid_t *)(data + 4 * sizeof(hid_t) + sizeof(char *));
    hid_t dapl_id = *(hid_t *)(data + 5 * sizeof(hid_t) + sizeof(char *));

    // Ensure the name is null-terminated and not empty
    size_t name_length = size - 6 * sizeof(hid_t);
    if (name_length == 0) {
        return 0;
    }

    char *name_buffer = (char *)malloc(name_length + 1);
    if (name_buffer == NULL) {
        return 0;
    }
    memcpy(name_buffer, name, name_length);
    name_buffer[name_length] = '\0';

    // Check if name_buffer is empty after null-termination
    if (strlen(name_buffer) == 0) {
        free(name_buffer);
        return 0;
    }

    // Initialize HDF5 library
    if (H5open() < 0) {
        free(name_buffer);
        return 0;
    }

    // Create a file to ensure loc_id is valid
    hid_t file_id = H5Fcreate("fuzz_test_file.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        free(name_buffer);
        H5close();
        return 0;
    }

    // Use the file_id as the location identifier
    loc_id = file_id;

    // Create a simple dataspace if space_id is invalid
    if (space_id < 0) {
        hsize_t dims[1] = {10}; // Example dimension
        space_id = H5Screate_simple(1, dims, NULL);
    }

    // Use default type if type_id is invalid
    if (type_id < 0) {
        type_id = H5T_NATIVE_INT;
    }

    // Use default property lists if any are invalid
    if (lcpl_id < 0) {
        lcpl_id = H5P_DEFAULT;
    }
    if (dcpl_id < 0) {
        dcpl_id = H5P_DEFAULT;
    }
    if (dapl_id < 0) {
        dapl_id = H5P_DEFAULT;
    }

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(loc_id, name_buffer, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up
    free(name_buffer);

    // Close the dataset if it was created successfully
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    // Close the dataspace if it was created
    if (space_id >= 0) {
        H5Sclose(space_id);
    }

    // Close the file
    H5Fclose(file_id);

    // Close HDF5 library
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_140(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
