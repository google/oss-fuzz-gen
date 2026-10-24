// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dget_access_plist at H5D.c:805:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dget_access_plist at H5D.c:805:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dget_access_plist at H5D.c:805:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dget_access_plist at H5D.c:805:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dget_access_plist at H5D.c:805:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <hdf5.h>
#include "H5Dpublic.h"
#include "H5Fpublic.h"

static hid_t create_dataspace() {
    hsize_t dims[1] = {10};
    return H5Screate_simple(1, dims, NULL);
}

static hid_t create_datatype() {
    return H5Tcopy(H5T_NATIVE_INT);
}

int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new HDF5 file
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a dataspace and datatype
    hid_t space_id = create_dataspace();
    hid_t type_id = create_datatype();

    // Create a new dataset
    hid_t dset_id = H5Dcreate2(file_id, "dataset1", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id >= 0) {
        // Get access property list
        hid_t dapl_id = H5Dget_access_plist(dset_id);
        if (dapl_id >= 0) H5Pclose(dapl_id);

        // Close the dataset
        H5Dclose(dset_id);
    }

    // Open the dataset again
    dset_id = H5Dopen2(file_id, "dataset1", H5P_DEFAULT);
    if (dset_id >= 0) {
        hid_t dapl_id = H5Dget_access_plist(dset_id);
        if (dapl_id >= 0) H5Pclose(dapl_id);

        H5Dclose(dset_id);
    }

    // Create another dataset
    dset_id = H5Dcreate2(file_id, "dataset2", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id >= 0) {
        hid_t dapl_id = H5Dget_access_plist(dset_id);
        if (dapl_id >= 0) H5Pclose(dapl_id);

        H5Dclose(dset_id);
    }

    // Close the file
    H5Fclose(file_id);

    // Reopen the file
    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id >= 0) {
        // Open the dataset
        dset_id = H5Dopen2(file_id, "dataset1", H5P_DEFAULT);
        if (dset_id >= 0) {
            hid_t dapl_id = H5Dget_access_plist(dset_id);
            if (dapl_id >= 0) H5Pclose(dapl_id);

            H5Dclose(dset_id);
        }

        // Open the second dataset
        dset_id = H5Dopen2(file_id, "dataset2", H5P_DEFAULT);
        if (dset_id >= 0) {
            hid_t dapl_id = H5Dget_access_plist(dset_id);
            if (dapl_id >= 0) H5Pclose(dapl_id);

            H5Dclose(dset_id);
        }

        // Close the file
        H5Fclose(file_id);
    }

    // Cleanup
    H5Sclose(space_id);
    H5Tclose(type_id);

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

        LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    