#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Initialize a valid hid_t value
    hid_t file_id;

    // Create a new HDF5 file to obtain a valid file_id
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Failed to create a file, exit the fuzzer
    }

    // Call the function-under-test with the valid hid_t
    hid_t reopened_id = H5Freopen(file_id);

    // Clean up: Close the reopened file, if valid
    if (reopened_id >= 0) {
        H5Fclose(reopened_id);
    }

    // Clean up: Close the original file
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

    LLVMFuzzerTestOneInput_59(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
