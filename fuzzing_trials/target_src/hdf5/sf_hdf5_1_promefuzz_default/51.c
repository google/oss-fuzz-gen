// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fset_libver_bounds at H5F.c:2404:1 in H5Fpublic.h
// H5Gget_num_objs at H5Gdeprec.c:885:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <hdf5.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Dpublic.h"

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void fuzz_H5Fset_libver_bounds(hid_t file_id, const uint8_t *Data, size_t Size) {
    if (Size < 2) return;
    H5F_libver_t low = (H5F_libver_t)(Data[0] % H5F_LIBVER_NBOUNDS);
    H5F_libver_t high = (H5F_libver_t)(Data[1] % H5F_LIBVER_NBOUNDS);
    H5Fset_libver_bounds(file_id, low, high);
}

static void fuzz_H5Gget_num_objs(hid_t loc_id) {
    hsize_t num_objs;
    H5Gget_num_objs(loc_id, &num_objs);
}

static void fuzz_H5Gcreate2(hid_t loc_id, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    char name[256];
    snprintf(name, sizeof(name), "group_%u", Data[0]);
    hid_t group_id = H5Gcreate2(loc_id, name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gget_info(hid_t loc_id) {
    H5G_info_t ginfo;
    H5Gget_info(loc_id, &ginfo);
}

static void fuzz_H5Glink2(hid_t loc_id, const uint8_t *Data, size_t Size) {
    if (Size < 2) return;
    char cur_name[256];
    char new_name[256];
    snprintf(cur_name, sizeof(cur_name), "cur_%u", Data[0]);
    snprintf(new_name, sizeof(new_name), "new_%u", Data[1]);
    H5Glink2(loc_id, cur_name, H5L_TYPE_HARD, loc_id, new_name);
}

static void fuzz_H5Dwrite(hid_t loc_id, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    hid_t space_id = H5Screate(H5S_SIMPLE);
    if (space_id < 0) return;
    hsize_t dims[1] = {Size};
    H5Sset_extent_simple(space_id, 1, dims, NULL);
    hid_t dset_id = H5Dcreate2(loc_id, "dataset", H5T_NATIVE_UCHAR, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id >= 0) {
        H5Dwrite(dset_id, H5T_NATIVE_UCHAR, H5S_ALL, H5S_ALL, H5P_DEFAULT, Data);
        H5Dclose(dset_id);
    }
    H5Sclose(space_id);
}

int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0;

    fuzz_H5Fset_libver_bounds(file_id, Data, Size);
    fuzz_H5Gget_num_objs(file_id);
    fuzz_H5Gcreate2(file_id, Data, Size);
    fuzz_H5Gget_info(file_id);
    fuzz_H5Glink2(file_id, Data, Size);
    fuzz_H5Dwrite(file_id, Data, Size);

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

        LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    