#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_229(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary file to work with
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a group in the file
    hid_t group_id = H5Gcreate(file_id, "/group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Ensure we have enough data to work with
    if (size < 2) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Split the data into two parts for source and destination names
    size_t mid = size / 2;
    char *src_name = (char *)malloc(mid + 1);
    char *dst_name = (char *)malloc(size - mid + 1);

    if (src_name == NULL || dst_name == NULL) {
        free(src_name);
        free(dst_name);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    memcpy(src_name, data, mid);
    src_name[mid] = '\0';

    memcpy(dst_name, data + mid, size - mid);
    dst_name[size - mid] = '\0';

    // Call the function-under-test
    herr_t status = H5Gmove(group_id, src_name, dst_name);

    // Clean up
    free(src_name);
    free(dst_name);
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

    LLVMFuzzerTestOneInput_229(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
