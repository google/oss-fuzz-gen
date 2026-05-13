// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dget_space at H5D.c:597:1 in H5Dpublic.h
// H5Dget_space at H5D.c:597:1 in H5Dpublic.h
// H5Dget_create_plist at H5D.c:747:1 in H5Dpublic.h
// H5Dget_create_plist at H5D.c:747:1 in H5Dpublic.h
// H5Dget_space_status at H5D.c:668:1 in H5Dpublic.h
// H5Dget_space_status at H5D.c:668:1 in H5Dpublic.h
// H5Dget_storage_size at H5D.c:848:1 in H5Dpublic.h
// H5Dget_storage_size at H5D.c:848:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Dpublic.h"
#include "H5Spublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"

static hid_t create_dummy_dataset() {
    // Create a dummy file and dataset for testing
    hid_t file_id, space_id, dset_id;
    hsize_t dims[1] = {10};

    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return -1;

    space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) {
        H5Fclose(file_id);
        return -1;
    }

    dset_id = H5Dcreate2(file_id, "dset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return -1;
    }

    H5Sclose(space_id);
    H5Fclose(file_id);
    return dset_id;
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    hid_t dset_id, type_id1, type_id2, space_id1, space_id2, plist_id1, plist_id2;
    H5D_space_status_t space_status1, space_status2;
    hsize_t storage_size1, storage_size2;
    herr_t status;
    int buffer[10];

    dset_id = create_dummy_dataset();
    if (dset_id < 0) return 0;

    // H5Dget_type
    type_id1 = H5Dget_type(dset_id);
    type_id2 = H5Dget_type(dset_id);

    // H5Dget_space
    space_id1 = H5Dget_space(dset_id);
    space_id2 = H5Dget_space(dset_id);

    // H5Dget_create_plist
    plist_id1 = H5Dget_create_plist(dset_id);
    plist_id2 = H5Dget_create_plist(dset_id);

    // H5Dget_space_status
    status = H5Dget_space_status(dset_id, &space_status1);
    status = H5Dget_space_status(dset_id, &space_status2);

    // H5Dget_storage_size
    storage_size1 = H5Dget_storage_size(dset_id);
    storage_size2 = H5Dget_storage_size(dset_id);

    // H5Dread
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, buffer);
    status = H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, buffer);

    // Cleanup
    if (type_id1 >= 0) H5Tclose(type_id1);
    if (type_id2 >= 0) H5Tclose(type_id2);
    if (space_id1 >= 0) H5Sclose(space_id1);
    if (space_id2 >= 0) H5Sclose(space_id2);
    if (plist_id1 >= 0) H5Pclose(plist_id1);
    if (plist_id2 >= 0) H5Pclose(plist_id2);
    if (dset_id >= 0) H5Dclose(dset_id);

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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    