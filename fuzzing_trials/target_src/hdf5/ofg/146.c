#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    hid_t loc_id = H5I_INVALID_HID;
    hid_t child_id = H5I_INVALID_HID;
    hid_t plist_id = H5P_DEFAULT;
    herr_t status;
    char filename[256];
    int fd;
    
    // Create a temporary file to use as a mount point
    snprintf(filename, sizeof(filename), "/tmp/fuzzfileXXXXXX");
    fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Initialize HDF5 library
    H5open();
    
    // Create a new HDF5 file to be used as the location and child
    loc_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (loc_id < 0) {
        goto cleanup;
    }
    
    child_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (child_id < 0) {
        goto cleanup;
    }

    // Call the function-under-test
    status = H5Fmount(loc_id, "/mount_point", child_id, plist_id);

cleanup:
    // Close the HDF5 files
    if (loc_id >= 0) {
        H5Fclose(loc_id);
    }
    if (child_id >= 0) {
        H5Fclose(child_id);
    }

    // Remove the temporary file
    unlink(filename);

    // Close HDF5 library
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

    LLVMFuzzerTestOneInput_146(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
