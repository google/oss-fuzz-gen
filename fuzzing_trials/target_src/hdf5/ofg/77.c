#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < 10) {
        return 0;
    }

    // Initialize HDF5 library
    H5open();

    // Create a new file using the default properties.
    hid_t file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

    // Create a group in the file.
    hid_t group_id = H5Gcreate2(file_id, "/fuzz_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    // Prepare parameters for H5Gget_linkval
    const char *name = "/fuzz_group";
    size_t buf_size = size < 256 ? size : 256; // Limit buffer size
    char *linkval = (char *)malloc(buf_size);
    if (linkval == NULL) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Call the function-under-test
    herr_t status = H5Gget_linkval(group_id, name, buf_size, linkval);

    // Clean up
    free(linkval);
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

    LLVMFuzzerTestOneInput_77(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
