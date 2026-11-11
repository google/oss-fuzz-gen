#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t file_id;
    char *path;
    char *comment;
    herr_t status;

    // Ensure size is sufficient to create strings
    if (size < 4) return 0;

    // Create a temporary file in memory
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Allocate memory for path and comment
    path = (char *)malloc((size / 2) + 1);
    comment = (char *)malloc((size / 2) + 1);
    if (path == NULL || comment == NULL) {
        H5Fclose(file_id);
        return 0;
    }

    // Copy data into path and comment, ensuring null-termination
    memcpy(path, data, size / 2);
    path[size / 2] = '\0';
    memcpy(comment, data + (size / 2), size / 2);
    comment[size / 2] = '\0';

    // Call the function-under-test
    status = H5Gset_comment(file_id, path, comment);

    // Cleanup
    free(path);
    free(comment);
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

    LLVMFuzzerTestOneInput_172(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
