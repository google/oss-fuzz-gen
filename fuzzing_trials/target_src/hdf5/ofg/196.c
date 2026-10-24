#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_196(const uint8_t *data, size_t size) {
    hid_t file_id;
    herr_t status;
    char filename[] = "fuzz_test_file.h5";

    // Create an HDF5 file to ensure we have a valid file_id
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    
    // Check if file creation was successful
    if (file_id < 0) {
        return 0; // Exit if file creation failed
    }

    // Call the function-under-test
    status = H5Fclose(file_id);

    // Remove the temporary file
    remove(filename);

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

    LLVMFuzzerTestOneInput_196(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
