#include <stdint.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_195(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a valid file name
    if (size < 5) {
        return 0;
    }

    // Create a temporary file name from the input data
    char filename[6];
    for (size_t i = 0; i < 5; i++) {
        filename[i] = (char)data[i] % 26 + 'a'; // Ensure it's a valid character
    }
    filename[5] = '\0'; // Null-terminate the string

    // Create an HDF5 file
    hid_t file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Failed to create file, exit
    }

    // Close the HDF5 file
    herr_t status = H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_195(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
