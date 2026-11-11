#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Initialize the HDF5 library
    H5open();

    // Create a temporary HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a group in the file
    hid_t group_id = H5Gcreate(file_id, "/testgroup", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Ensure the data is null-terminated for the object name
    char object_name[256];
    size_t name_length = size < 255 ? size : 255;
    memcpy(object_name, data, name_length);
    object_name[name_length] = '\0';

    // Prepare the H5G_stat_t structure
    H5G_stat_t statbuf;

    // Call the function-under-test
    herr_t status = H5Gget_objinfo(group_id, object_name, true, &statbuf);

    // Clean up
    H5Gclose(group_id);
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

    LLVMFuzzerTestOneInput_41(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
