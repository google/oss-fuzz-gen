#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_214(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a temporary HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Failed to create file, exit early
    }

    // Allocate memory for H5F_info2_t structure
    H5F_info2_t file_info;
    
    // Call the function-under-test
    herr_t status = H5Fget_info2(file_id, &file_info);

    // Close the file
    H5Fclose(file_id);

    // Ensure HDF5 library is closed
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

    LLVMFuzzerTestOneInput_214(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
