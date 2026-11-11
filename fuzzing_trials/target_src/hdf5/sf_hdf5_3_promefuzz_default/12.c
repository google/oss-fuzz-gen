// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dwrite_multi at H5D.c:1419:1 in H5Dpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>

static void write_dummy_data_to_file() {
    // Create a dummy HDF5 file with necessary datasets and groups
    hid_t file_id, group_id, dataset_id, space_id;
    hsize_t dims[1] = {10};
    int data[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    group_id = H5Gcreate2(file_id, "/group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    space_id = H5Screate_simple(1, dims, NULL);
    dataset_id = H5Dcreate2(group_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Dwrite(dataset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);

    H5Dclose(dataset_id);
    H5Sclose(space_id);
    H5Gclose(group_id);
    H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t)) return 0;

    write_dummy_data_to_file();

    // Open the dummy file
    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Attempt to open the dataset
    hid_t dataset_id = H5Dopen2(file_id, "/group/dataset", H5P_DEFAULT);
    if (dataset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Try to get the datatype of the dataset
    hid_t type_id = H5Dget_type(dataset_id);
    if (type_id >= 0) {
        H5Tclose(type_id);
    }

    // Try to read from the dataset
    int buf[10];
    herr_t status = H5Dread(dataset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, buf);
    if (status < 0) {
        // Handle read error if necessary
    }

    // Try to write to multiple datasets (although we have only one for now)
    hid_t dset_ids[1] = {dataset_id};
    hid_t mem_type_ids[1] = {H5T_NATIVE_INT};
    hid_t mem_space_ids[1] = {H5S_ALL};
    hid_t file_space_ids[1] = {H5S_ALL};
    const void *bufs[1] = {buf};
    status = H5Dwrite_multi(1, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, H5P_DEFAULT, bufs);
    if (status < 0) {
        // Handle write error if necessary
    }

    // Create another group
    hid_t new_group_id = H5Gcreate2(file_id, "/new_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (new_group_id >= 0) {
        H5Gclose(new_group_id);
    }

    // Cleanup
    H5Dclose(dataset_id);
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

        LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    