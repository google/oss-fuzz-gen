// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fget_access_plist at H5F.c:152:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Fget_access_plist at H5F.c:152:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dflush at H5D.c:2055:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <H5Dpublic.h>
#include <H5Fpublic.h>
#include <H5Ppublic.h>
#include <H5Spublic.h>
#include <H5Tpublic.h>

static void write_dummy_file() {
    // Write necessary data to "./dummy_file"
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "Dummy data for HDF5 testing.");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare dummy file
    write_dummy_file();

    // Initialize variables
    hid_t file_id = -1, dset_id1 = -1, dset_id2 = -1, plist_id = -1, space_id = -1;
    herr_t status;
    const char *filename = "./dummy_file";
    const char *dset_name1 = "dataset1";
    const char *dset_name2 = "dataset2";
    space_id = H5Screate(H5S_SCALAR);
    hid_t type_id = H5T_NATIVE_INT;
    int buf = 42;

    // Create a new file
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) goto cleanup;

    // Get file access property list
    plist_id = H5Fget_access_plist(file_id);
    if (plist_id < 0) goto cleanup;

    // Close the file
    status = H5Fclose(file_id);
    if (status < 0) goto cleanup;

    // Open the file
    file_id = H5Fopen(filename, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) goto cleanup;

    // Create a new dataset
    dset_id1 = H5Dcreate2(file_id, dset_name1, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id1 < 0) goto cleanup;

    // Write data to dataset
    status = H5Dwrite(dset_id1, type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, &buf);
    if (status < 0) goto cleanup;

    // Get file access property list again
    plist_id = H5Fget_access_plist(file_id);
    if (plist_id < 0) goto cleanup;

    // Create another dataset
    dset_id2 = H5Dcreate2(file_id, dset_name2, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id2 < 0) goto cleanup;

    // Flush dataset
    status = H5Dflush(dset_id2);
    if (status < 0) goto cleanup;

cleanup:
    // Close datasets and file
    if (dset_id1 >= 0) H5Dclose(dset_id1);
    if (dset_id2 >= 0) H5Dclose(dset_id2);
    if (file_id >= 0) H5Fclose(file_id);
    if (space_id >= 0) H5Sclose(space_id);
    if (plist_id >= 0) H5Pclose(plist_id);

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

        LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    