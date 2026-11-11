#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create valid inputs
    if (size < 2) return 0;

    // Create a valid HDF5 file to work with
    hid_t file_id = H5Fcreate("fuzz_test.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a group inside the file
    hid_t group_id = H5Gcreate(file_id, "/test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Set a comment for the group
    const char *comment = "This is a test comment";
    H5Gset_comment(group_id, ".", comment);

    // Prepare inputs for H5Gget_comment
    const char *name = ".";
    size_t bufsize = (size_t)data[0]; // Use first byte of data as buffer size
    char *buf = (char *)malloc(bufsize);
    if (buf == NULL) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Call the function-under-test
    H5Gget_comment(group_id, name, bufsize, buf);

    // Clean up
    free(buf);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_75(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
