#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary file to use with HDF5
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Failed to create file, exit
    }

    // Create a group in the file
    hid_t group_id = H5Gcreate(file_id, "group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0; // Failed to create group, exit
    }

    // Ensure size is sufficient for a valid string and buffer
    if (size < 2) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Use part of the data as the link name
    size_t link_name_len = size / 2;
    char *link_name = (char *)malloc(link_name_len + 1);
    if (link_name == NULL) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0; // Failed to allocate memory, exit
    }
    memcpy(link_name, data, link_name_len);
    link_name[link_name_len] = '\0';

    // Use the rest of the data as the buffer
    size_t buffer_size = size - link_name_len;
    char *buffer = (char *)malloc(buffer_size);
    if (buffer == NULL) {
        free(link_name);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0; // Failed to allocate memory, exit
    }

    // Call the function-under-test
    herr_t status = H5Gget_linkval(group_id, link_name, buffer_size, buffer);

    // Clean up
    free(link_name);
    free(buffer);
    H5Gclose(group_id);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_78(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
