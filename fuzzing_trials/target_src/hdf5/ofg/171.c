#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include this for memcpy
#include <hdf5.h>

int LLVMFuzzerTestOneInput_171(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary HDF5 file
    hid_t file_id = H5Fcreate("temp.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Ensure the data size is sufficient for creating strings
    if (size < 2) {
        H5Fclose(file_id);
        return 0;
    }

    // Split the data into two parts for the object name and comment
    size_t half_size = size / 2;
    char *object_name = (char *)malloc(half_size + 1);
    char *comment = (char *)malloc(size - half_size + 1);

    if (!object_name || !comment) {
        free(object_name);
        free(comment);
        H5Fclose(file_id);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(object_name, data, half_size);
    object_name[half_size] = '\0';

    memcpy(comment, data + half_size, size - half_size);
    comment[size - half_size] = '\0';

    // Call the function-under-test
    H5Gset_comment(file_id, object_name, comment);

    // Clean up
    free(object_name);
    free(comment);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_171(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
