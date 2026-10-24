#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_248(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    if (H5open() < 0) {
        return 0;
    }

    // Create a new file using the default properties.
    hid_t file_id = H5Fcreate("testfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a dataspace. Assume a simple scalar dataspace for this example.
    hid_t dataspace_id = H5Screate(H5S_SCALAR);
    if (dataspace_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create a datatype. Assume a native integer type for this example.
    hid_t datatype_id = H5Tcopy(H5T_NATIVE_INT);
    if (datatype_id < 0) {
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0;
    }

    // Create an attribute creation property list. Use the default in this example.
    hid_t acpl_id = H5Pcreate(H5P_ATTRIBUTE_CREATE);
    if (acpl_id < 0) {
        H5Tclose(datatype_id);
        H5Sclose(dataspace_id);
        H5Fclose(file_id);
        return 0;
    }

    // Use the first part of the data as the attribute name, ensuring it's null-terminated.
    char attr_name[256];
    size_t name_len = (size < 255) ? size : 255;
    memcpy(attr_name, data, name_len);
    attr_name[name_len] = '\0';

    // Call the function under test
    hid_t attribute_id = H5Acreate1(file_id, attr_name, datatype_id, dataspace_id, acpl_id);

    // Clean up
    if (attribute_id >= 0) {
        H5Aclose(attribute_id);
    }
    H5Pclose(acpl_id);
    H5Tclose(datatype_id);
    H5Sclose(dataspace_id);
    H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_248(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
