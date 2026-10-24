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

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from H5Acreate2 to H5Dcreate_anon
    hid_t ret_H5Dget_access_plist_aqqqc = H5Dget_access_plist(attr_id);
    hid_t ret_H5Dget_access_plist_oxgnj = H5Dget_access_plist(file_id);
    hid_t ret_H5Dget_create_plist_ezhta = H5Dget_create_plist(dset_id);
    hid_t ret_H5Aget_create_plist_viokn = H5Aget_create_plist(attr_id);
    hid_t ret_H5Dcreate_anon_jjmah = H5Dcreate_anon(ret_H5Dget_access_plist_aqqqc, attr_id, ret_H5Dget_access_plist_oxgnj, ret_H5Dget_create_plist_ezhta, ret_H5Aget_create_plist_viokn);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from H5Dcreate_anon to H5Aread
    hid_t ret_H5Dget_space_nghpv = H5Dget_space(attr_id);
    herr_t ret_H5Aread_xcpws = H5Aread(ret_H5Dget_space_nghpv, ret_H5Dcreate_anon_jjmah, NULL);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from H5Dread to H5Gunlink
    hid_t ret_H5Aget_type_otctp = H5Aget_type(attr_id);
    // Ensure dataflow is valid (i.e., non-null)
    if (!data) {
    	return 0;
    }
    herr_t ret_H5Gunlink_mkahx = H5Gunlink(ret_H5Aget_type_otctp, (const char *)data);
    // End mutation: Producer.APPEND_MUTATOR
    
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status < 0) {
        goto cleanup;
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from H5Dread to H5Fget_name
    hid_t ret_H5Dget_create_plist_wizvt = H5Dget_create_plist(file_id);
    // Ensure dataflow is valid (i.e., non-null)
    if (!data) {
    	return 0;
    }
    ssize_t ret_H5Fget_name_izopi = H5Fget_name(ret_H5Dget_create_plist_wizvt, (char *)data, H5D_CHUNK_CACHE_W0_DEFAULT);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
