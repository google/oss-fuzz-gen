#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/hdf5/src/H5Dpublic.h"
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Apublic.h"
#include "/src/hdf5/src/H5Spublic.h"
#include "/src/hdf5/src/H5Tpublic.h"
#include "/src/hdf5/src/H5Ppublic.h"

static herr_t dummy_iterate(void *elem, hid_t type_id, unsigned ndim, const hsize_t *point, void *operator_data) {
    return 0;
}

int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a dummy file
    FILE *file = fopen("./dummy_file", "w");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the HDF5 file
    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a simple dataspace
    hsize_t dims[1] = {10};
    hid_t space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create a dataset
    hid_t dset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    int data[10] = {0};
    herr_t status;

    // Write to the dataset
    status = H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) {
        goto cleanup;
    }

    // Write to the dataset again
    status = H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) {
        goto cleanup;
    }

    // Write to the dataset again
    status = H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) {
        goto cleanup;
    }

    // Iterate over dataset
    status = H5Diterate(data, H5T_NATIVE_INT, space_id, dummy_iterate, NULL);
    if (status < 0) {
        goto cleanup;
    }

    // Fill the dataset

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from H5Diterate to H5Aexists_by_name
    hid_t ret_H5Dget_access_plist_ztrzy = H5Dget_access_plist(file_id);
    hid_t ret_H5Aget_space_vtkrv = H5Aget_space(file_id);
    // Ensure dataflow is valid (i.e., non-null)
    if (!data) {
    	return 0;
    }
    htri_t ret_H5Aexists_by_name_btbvn = H5Aexists_by_name(ret_H5Dget_access_plist_ztrzy, (const char *)data, (const char *)data, ret_H5Aget_space_vtkrv);
    // End mutation: Producer.APPEND_MUTATOR
    
    status = H5Dfill(NULL, H5T_NATIVE_INT, data, H5T_NATIVE_INT, space_id);
    if (status < 0) {
        goto cleanup;
    }

    // Create an attribute
    hid_t attr_id = H5Acreate2(dset_id, "attribute", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id < 0) {
        goto cleanup;
    }

    // Read from the dataset
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) {
        goto cleanup;
    }

    // Read from the dataset again
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) {
        goto cleanup;
    }

    // Read from the dataset again
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) {
        goto cleanup;
    }

cleanup:
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }
    if (dset_id >= 0) {
        H5Dclose(dset_id);
    }
    if (space_id >= 0) {
        H5Sclose(space_id);
    }
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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
