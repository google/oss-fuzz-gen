#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our needs
    if (size < 3) return 0;

    // Initialize HDF5 library
    H5open();

    // Create a temporary file to work with
    char tmpl[] = "/tmp/hdf5fuzzXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) return 0;
    close(fd);

    // Create an HDF5 file
    hid_t file_id = H5Fcreate(tmpl, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        unlink(tmpl);
        return 0;
    }

    // Prepare the group name from the input data
    size_t name_length = size - 3;
    char *group_name = (char *)malloc(name_length + 1);
    if (!group_name) {
        H5Fclose(file_id);
        unlink(tmpl);
        return 0;
    }
    memcpy(group_name, data, name_length);
    group_name[name_length] = '\0';

    // Extract hid_t parameters from the input data
    hid_t lcpl_id = (hid_t)data[size - 3];
    hid_t gcpl_id = (hid_t)data[size - 2];
    hid_t gapl_id = (hid_t)data[size - 1];

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Clean up
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
    H5Fclose(file_id);
    unlink(tmpl);
    free(group_name);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
