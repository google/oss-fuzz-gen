#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hdf5.h"

static void write_dummy_file() {
    // Create a new HDF5 file using default properties.
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    
    // Create a dataset within the file.
    hsize_t dims[1] = {10};
    hid_t space_id = H5Screate_simple(1, dims, NULL);
    hid_t dset_id = H5Dcreate2(file_id, "dset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    
    // Create an attribute for the dataset.
    hid_t attr_id = H5Acreate(dset_id, "attr", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT);
    H5Aclose(attr_id);
    
    // Close the dataset and file.
    H5Dclose(dset_id);
    H5Sclose(space_id);
    H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data to work with

    // Write the dummy file to ensure it exists
    write_dummy_file();

    // Open the HDF5 file
    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Open dataset
    hid_t dset_id = H5Dopen2(file_id, "dset", H5P_DEFAULT);
    if (dset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Get number of attributes
    int num_attrs = H5Aget_num_attrs(dset_id);
    if (num_attrs < 0) {
        H5Dclose(dset_id);
        H5Fclose(file_id);
        return 0;
    }

    // Open attribute by index
    if (num_attrs > 0) {
        hid_t attr_id = H5Aopen_idx(dset_id, 0);
        if (attr_id >= 0) {
            H5Aclose(attr_id);
        }
    }

    // Open attribute by name
    hid_t attr_id = H5Aopen_name(dset_id, "attr");
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // Close dataset
    H5Dclose(dset_id);

    // Close file
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
