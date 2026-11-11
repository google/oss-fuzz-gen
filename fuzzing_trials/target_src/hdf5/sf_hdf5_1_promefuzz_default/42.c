// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Dget_chunk_storage_size at H5D.c:2218:1 in H5Dpublic.h
// H5Fget_info2 at H5F.c:2055:1 in H5Fpublic.h
// H5Drefresh at H5D.c:2096:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Fpublic.h>
#include <H5Gpublic.h>
#include <H5Dpublic.h>
#include <H5Spublic.h>
#include <H5Ppublic.h>
#include <H5Tpublic.h>

static void fuzz_H5Gget_info(hid_t loc_id) {
    H5G_info_t ginfo;
    H5Gget_info(loc_id, &ginfo);
}

static void fuzz_H5Dget_chunk_storage_size(hid_t dset_id) {
    hsize_t offset[1] = {0};
    hsize_t chunk_bytes;
    H5Dget_chunk_storage_size(dset_id, offset, &chunk_bytes);
}

static void fuzz_H5Fget_info2(hid_t obj_id) {
    H5F_info2_t file_info;
    H5Fget_info2(obj_id, &file_info);
}

static void fuzz_H5Drefresh(hid_t dset_id) {
    H5Drefresh(dset_id);
}

static void fuzz_H5Dread(hid_t dset_id) {
    hid_t mem_type_id = H5T_NATIVE_INT;
    hid_t mem_space_id = H5S_ALL;
    hid_t file_space_id = H5S_ALL;
    hid_t dxpl_id = H5P_DEFAULT;
    int buf[1024];
    H5Dread(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf);
}

static void fuzz_H5Dwrite(hid_t dset_id) {
    hid_t mem_type_id = H5T_NATIVE_INT;
    hid_t mem_space_id = H5S_ALL;
    hid_t file_space_id = H5S_ALL;
    hid_t dxpl_id = H5P_DEFAULT;
    int buf[1024] = {0};
    H5Dwrite(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf);
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    // Create a dummy HDF5 file and dataset for testing
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t space_id = H5Screate(H5S_SIMPLE);
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hsize_t dims[1] = {1024};
    H5Sset_extent_simple(space_id, 1, dims, NULL);

    hid_t dset_id = H5Dcreate2(file_id, "dset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Fuzz each function with the created identifiers
    fuzz_H5Gget_info(file_id);
    fuzz_H5Dget_chunk_storage_size(dset_id);
    fuzz_H5Fget_info2(file_id);
    fuzz_H5Drefresh(dset_id);
    fuzz_H5Dread(dset_id);
    fuzz_H5Dwrite(dset_id);

    // Cleanup
    H5Dclose(dset_id);
    H5Sclose(space_id);
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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    