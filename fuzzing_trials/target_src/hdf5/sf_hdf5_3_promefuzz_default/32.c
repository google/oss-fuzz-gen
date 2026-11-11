// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dwrite_multi at H5D.c:1419:1 in H5Dpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "H5Dpublic.h"
#include "H5Gpublic.h"
#include "H5Fpublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"
#include "H5Ppublic.h"

static void initialize_hdf5(void) {
    // Initialize HDF5 library if necessary
}

static void cleanup_hdf5(void) {
    // Cleanup HDF5 resources if necessary
}

int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    initialize_hdf5();

    // Create a dummy HDF5 file
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a dummy group
    hid_t group_id = H5Gcreate2(file_id, "group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create a dataspace
    hsize_t dims[1] = {10};
    hid_t space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Create a dataset
    hid_t dset_id = H5Dcreate2(group_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Ensure the input buffer is large enough
    if (Size < 10 * sizeof(int)) {
        H5Dclose(dset_id);
        H5Sclose(space_id);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Fuzz H5Dwrite_multi
    size_t count = 1;
    hid_t dset_ids[] = {dset_id};
    hid_t mem_type_ids[] = {H5T_NATIVE_INT};
    hid_t mem_space_ids[] = {H5S_ALL};
    hid_t file_space_ids[] = {H5S_ALL};
    hid_t dxpl_id = H5P_DEFAULT;
    const void *buf[] = {Data};

    H5Dwrite_multi(count, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, dxpl_id, buf);

    // Fuzz H5Dget_type
    hid_t type_id = H5Dget_type(dset_id);
    if (type_id >= 0) {
        H5Tclose(type_id);
    }

    // Fuzz H5Dread
    int read_buf[10];
    H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, read_buf);

    // Cleanup
    H5Dclose(dset_id);
    H5Sclose(space_id);
    H5Gclose(group_id);
    H5Fclose(file_id);

    cleanup_hdf5();
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

        LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    