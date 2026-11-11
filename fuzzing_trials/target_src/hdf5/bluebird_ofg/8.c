#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for a valid string
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to serve as an HDF5 file
    hid_t file_id;
    char file_name[] = "tempfile.h5";
    file_id = H5Fcreate(file_name, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

    // Ensure the file was created successfully
    if (file_id < 0) {
        return 0;
    }

    // Create a group within the file
    hid_t group_id;
    group_id = H5Gcreate2(file_id, "/test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    // Ensure the group was created successfully
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create a null-terminated string from the input data
    char *group_name = (char *)malloc(size + 1);
    if (group_name == NULL) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }
    memcpy(group_name, data, size);
    group_name[size] = '\0';

    // Call the function-under-test
    H5Gunlink(file_id, group_name);

    // Clean up
    free(group_name);
    H5Gclose(group_id);
    H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
