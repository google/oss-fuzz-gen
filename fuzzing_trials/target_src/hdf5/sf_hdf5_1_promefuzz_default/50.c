// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fset_libver_bounds at H5F.c:2404:1 in H5Fpublic.h
// H5Gget_num_objs at H5Gdeprec.c:885:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
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
#include <H5Ppublic.h>
#include <H5Spublic.h>
#include <H5Tpublic.h>

#define DUMMY_FILE "./dummy_file"

static void fuzz_H5Fset_libver_bounds(hid_t file_id) {
    H5F_libver_t low = (H5F_libver_t)(rand() % H5F_LIBVER_NBOUNDS);
    H5F_libver_t high = (H5F_libver_t)(rand() % H5F_LIBVER_NBOUNDS);
    H5Fset_libver_bounds(file_id, low, high);
}

static void fuzz_H5Gget_num_objs(hid_t loc_id) {
    hsize_t num_objs;
    H5Gget_num_objs(loc_id, &num_objs);
}

static void fuzz_H5Gcreate2(hid_t loc_id) {
    hid_t group_id = H5Gcreate2(loc_id, "test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gget_info(hid_t loc_id) {
    H5G_info_t ginfo;
    H5Gget_info(loc_id, &ginfo);
}

static void fuzz_H5Glink2(hid_t cur_loc_id, hid_t new_loc_id) {
    H5Glink2(cur_loc_id, "cur_name", H5G_LINK_HARD, new_loc_id, "new_name");
}

static void fuzz_H5Dwrite(hid_t dset_id) {
    int data = 42;
    H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, &data);
}

int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    // Create a dummy file
    FILE *file = fopen(DUMMY_FILE, "w");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open HDF5 file
    hid_t file_id = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Fuzz each function
    fuzz_H5Fset_libver_bounds(file_id);
    fuzz_H5Gget_num_objs(file_id);
    fuzz_H5Gcreate2(file_id);
    fuzz_H5Gget_info(file_id);
    fuzz_H5Glink2(file_id, file_id);

    // Create a dummy dataset
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t dset_id = H5Dcreate2(file_id, "test_dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id >= 0) {
        fuzz_H5Dwrite(dset_id);
        H5Dclose(dset_id);
    }
    H5Sclose(space_id);

    // Close the file
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

        LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    