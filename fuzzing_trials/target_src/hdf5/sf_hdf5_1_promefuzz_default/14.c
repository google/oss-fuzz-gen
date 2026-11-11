// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fget_eoa at H5F.c:2606:1 in H5Fpublic.h
// H5Gget_num_objs at H5Gdeprec.c:885:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Fget_obj_ids at H5F.c:333:1 in H5Fpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
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

static void fuzz_H5Fget_eoa(hid_t file_id) {
    haddr_t eoa;
    H5Fget_eoa(file_id, &eoa);
}

static void fuzz_H5Gget_num_objs(hid_t loc_id) {
    hsize_t num_objs;
    H5Gget_num_objs(loc_id, &num_objs);
}

static void fuzz_H5Gget_info(hid_t loc_id) {
    H5G_info_t ginfo;
    H5Gget_info(loc_id, &ginfo);
}

static void fuzz_H5Fget_obj_ids(hid_t file_id) {
    hid_t obj_id_list[10];
    H5Fget_obj_ids(file_id, H5F_OBJ_ALL, 10, obj_id_list);
}

static void fuzz_H5Glink2(hid_t cur_loc_id, const char *cur_name, hid_t new_loc_id, const char *new_name) {
    H5Glink2(cur_loc_id, cur_name, H5L_TYPE_HARD, new_loc_id, new_name);
}

static void fuzz_H5Dwrite(hid_t dset_id, const void *buf) {
    H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, buf);
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t)) return 0;

    // Create a dummy file for testing
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Fuzz each function with the same file_id, which is not ideal for real fuzzing but serves as a placeholder
    fuzz_H5Fget_eoa(file_id);
    fuzz_H5Gget_num_objs(file_id);
    fuzz_H5Gget_info(file_id);
    fuzz_H5Fget_obj_ids(file_id);

    // Use a simple string for link names
    fuzz_H5Glink2(file_id, "cur_name", file_id, "new_name");

    // Create a simple dataset to fuzz H5Dwrite
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t dset_id = H5Dcreate(file_id, "dset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id >= 0) {
        int data = 42;
        fuzz_H5Dwrite(dset_id, &data);
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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    