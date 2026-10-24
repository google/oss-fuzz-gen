#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"
#include <string.h>

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for two null-terminated strings
    if (size < 4) {
        return 0;
    }

    // Initialize HDF5 library
    H5open();

    // Create a new file using the default properties.
    hid_t file_id = H5Fcreate("temp.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

    // Create a dataspace
    hsize_t dims[1] = {10};
    hid_t dataspace_id = H5Screate_simple(1, dims, NULL);

    // Create an attribute
    hid_t attr_id = H5Acreate2(file_id, "attr1", H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT);

    // Split the data into two parts for old_name and new_name

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from H5Acreate2 to H5Dwrite
    hid_t ret_H5Dget_type_dnsqu = H5Dget_type(0);
    hid_t ret_H5Aget_space_pbckw = H5Aget_space(attr_id);
    hid_t ret_H5Dget_create_plist_dluri = H5Dget_create_plist(0);
    hid_t ret_H5Aget_create_plist_pmhvl = H5Aget_create_plist(attr_id);
    char rnrrhrfj[1024] = "ynepd";
    herr_t ret_H5Dwrite_mmciz = H5Dwrite(ret_H5Dget_type_dnsqu, attr_id, ret_H5Aget_space_pbckw, ret_H5Dget_create_plist_dluri, ret_H5Aget_create_plist_pmhvl, rnrrhrfj);
    // End mutation: Producer.APPEND_MUTATOR
    
    size_t half_size = size / 2;

    // Ensure null-terminated strings
    char old_name[half_size + 1];
    char new_name[size - half_size + 1];
    memcpy(old_name, data, half_size);
    memcpy(new_name, data + half_size, size - half_size);
    old_name[half_size] = '\0';
    new_name[size - half_size] = '\0';

    // Call the function-under-test
    herr_t status = H5Arename(file_id, old_name, new_name);

    // Clean up
    H5Aclose(attr_id);
    H5Sclose(dataspace_id);
    H5Fclose(file_id);
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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
