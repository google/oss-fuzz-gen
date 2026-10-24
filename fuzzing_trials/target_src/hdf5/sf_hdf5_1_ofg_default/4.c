#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

// Initialize the HDF5 library
__attribute__((constructor))
static void init_hdf5(void) {
    H5open();
}

// Fuzzing entry point
int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a valid HDF5 file
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to store HDF5 data
    char filename[] = "/tmp/fuzz_hdf5_XXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(filename);
        return 0;
    }
    close(fd);

    // Open the HDF5 file
    hid_t file_id = H5Fopen(filename, H5F_ACC_RDONLY, H5P_DEFAULT);
    if (file_id < 0) {
        unlink(filename);
        return 0;
    }

    // Prepare the group info structure
    H5G_info_t group_info;

    // Call the function-under-test
    herr_t status = H5Gget_info(file_id, &group_info);

    // Close the HDF5 file
    H5Fclose(file_id);

    // Clean up the temporary file
    unlink(filename);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
