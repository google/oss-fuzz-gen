#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_228(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < 4) return 0;

    // Initialize HDF5 library
    H5open();

    // Create a temporary HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a group in the file
    hid_t group_id = H5Gcreate(file_id, "/group1", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Split data for source and destination names
    size_t half_size = size / 2;
    char *source_name = (char *)malloc(half_size + 1);
    char *dest_name = (char *)malloc(size - half_size + 1);

    if (source_name == NULL || dest_name == NULL) {
        free(source_name);
        free(dest_name);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    memcpy(source_name, data, half_size);
    source_name[half_size] = '\0';  // Null-terminate the string

    memcpy(dest_name, data + half_size, size - half_size);
    dest_name[size - half_size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    herr_t status = H5Gmove(file_id, source_name, dest_name);

    // Clean up
    free(source_name);
    free(dest_name);
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

    LLVMFuzzerTestOneInput_228(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
