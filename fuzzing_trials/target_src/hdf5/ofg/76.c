#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    if (H5open() < 0) {
        return 0;
    }

    // Create a temporary file to work with
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, "/test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Ensure that the data size is sufficient to create a comment
    if (size < 1) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Create a comment buffer and copy data into it
    char *comment = (char *)malloc(size + 1);
    if (comment == NULL) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }
    memcpy(comment, data, size);
    comment[size] = '\0'; // Null-terminate the comment

    // Set a comment for the group
    if (H5Oset_comment(group_id, comment) < 0) {
        free(comment);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Prepare a buffer to retrieve the comment
    size_t comment_size = size + 1;
    char *retrieved_comment = (char *)malloc(comment_size);
    if (retrieved_comment == NULL) {
        free(comment);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Call the function-under-test
    H5Gget_comment(group_id, "/test_group", comment_size, retrieved_comment);

    // Clean up
    free(retrieved_comment);
    free(comment);
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

    LLVMFuzzerTestOneInput_76(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
