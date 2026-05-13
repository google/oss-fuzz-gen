#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_253(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t file_id = H5I_INVALID_HID;
    hid_t fapl_id = H5P_DEFAULT;
    void *vfd_handle = NULL;
    herr_t status;

    // Ensure the data size is sufficient for file creation
    if (size < 1) {
        return 0;
    }

    // Create a temporary HDF5 file
    const char *filename = "/tmp/tempfile.h5";
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Utilize the input data in some way
    // For example, we could write the data to the file or use it to modify some properties
    // Here we'll just demonstrate checking the first byte
    if (size > 0) {
        // Example logic using the data
        unsigned char first_byte = data[0];
        // Perform some operation based on the first byte
        // (This is just a placeholder for actual logic)
    }

    // Call the function-under-test
    status = H5Fget_vfd_handle(file_id, fapl_id, &vfd_handle);

    // Clean up
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

    LLVMFuzzerTestOneInput_253(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
