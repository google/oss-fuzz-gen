// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dget_access_plist at H5D.c:805:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dget_access_plist at H5D.c:805:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
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
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>
#include "H5Fpublic.h"
#include "H5Dpublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file != NULL) {
        fprintf(file, "Dummy content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    // Prepare dummy file
    write_dummy_file();

    // Initialize variables
    hid_t file_id = H5I_INVALID_HID;
    hid_t dataset_id = H5I_INVALID_HID;
    hid_t dapl_id = H5P_DEFAULT;
    hid_t dcpl_id = H5P_DEFAULT;
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t dtype_id = H5T_NATIVE_INT;
    hid_t space_id = H5Screate(H5S_SCALAR);
    herr_t status;

    // Ensure valid size for dataset name
    char dataset_name[256];
    snprintf(dataset_name, sizeof(dataset_name), "dataset_%zu", Size);

    // H5Fcreate
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) goto cleanup;

    // H5Dcreate2
    dataset_id = H5Dcreate2(file_id, dataset_name, dtype_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dataset_id < 0) goto cleanup;

    // H5Dget_access_plist
    hid_t dapl = H5Dget_access_plist(dataset_id);
    if (dapl >= 0) H5Pclose(dapl);

    // H5Dclose
    status = H5Dclose(dataset_id);
    if (status < 0) goto cleanup;

    // H5Dopen2
    dataset_id = H5Dopen2(file_id, dataset_name, dapl_id);
    if (dataset_id < 0) goto cleanup;

    // H5Dget_access_plist
    dapl = H5Dget_access_plist(dataset_id);
    if (dapl >= 0) H5Pclose(dapl);

    // H5Dclose
    status = H5Dclose(dataset_id);
    if (status < 0) goto cleanup;

    // H5Dcreate2
    dataset_id = H5Dcreate2(file_id, dataset_name, dtype_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dataset_id < 0) goto cleanup;

    // H5Dget_access_plist
    dapl = H5Dget_access_plist(dataset_id);
    if (dapl >= 0) H5Pclose(dapl);

    // H5Dclose
    status = H5Dclose(dataset_id);
    if (status < 0) goto cleanup;

    // H5Fclose
    status = H5Fclose(file_id);
    if (status < 0) goto cleanup;

    // H5Fopen
    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) goto cleanup;

    // H5Dopen2
    dataset_id = H5Dopen2(file_id, dataset_name, dapl_id);
    if (dataset_id < 0) goto cleanup;

    // H5Dget_access_plist
    dapl = H5Dget_access_plist(dataset_id);
    if (dapl >= 0) H5Pclose(dapl);

    // H5Dclose
    status = H5Dclose(dataset_id);
    if (status < 0) goto cleanup;

    // H5Dopen2
    dataset_id = H5Dopen2(file_id, dataset_name, dapl_id);
    if (dataset_id < 0) goto cleanup;

    // H5Dget_access_plist
    dapl = H5Dget_access_plist(dataset_id);
    if (dapl >= 0) H5Pclose(dapl);

    // H5Dclose
    status = H5Dclose(dataset_id);
    if (status < 0) goto cleanup;

    // H5Dget_access_plist
    dapl = H5Dget_access_plist(file_id);
    if (dapl >= 0) H5Pclose(dapl);

    // H5Dclose
    status = H5Dclose(file_id);
    if (status < 0) goto cleanup;

    // H5Fclose
    status = H5Fclose(file_id);
    if (status < 0) goto cleanup;

cleanup:
    if (file_id >= 0) H5Fclose(file_id);
    if (dataset_id >= 0) H5Dclose(dataset_id);
    if (space_id >= 0) H5Sclose(space_id);

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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    