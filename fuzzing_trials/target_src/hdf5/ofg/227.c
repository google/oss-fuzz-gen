#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_227(const uint8_t *data, size_t size) {
    hid_t file_id;
    ssize_t result;
    void *buffer = NULL;
    size_t buffer_size = size;

    // Initialize the HDF5 library
    H5open();

    // Create a temporary file to use for testing
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Allocate memory for the buffer
    if (buffer_size > 0) {
        buffer = malloc(buffer_size);
        if (buffer == NULL) {
            H5Fclose(file_id);
            return 0;
        }
        // Copy data into the buffer
        memcpy(buffer, data, buffer_size);
    }

    // Call the function-under-test
    result = H5Fget_file_image(file_id, buffer, buffer_size);

    // Clean up
    if (buffer != NULL) {
        free(buffer);
    }
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

    LLVMFuzzerTestOneInput_227(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
