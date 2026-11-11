// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fget_eoa at H5F.c:2606:1 in H5Fpublic.h
// H5Gget_num_objs at H5Gdeprec.c:885:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Fget_obj_ids at H5F.c:333:1 in H5Fpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Dpublic.h"
#include "H5Spublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"

static void fuzz_H5Fget_eoa(hid_t file_id) {
    haddr_t eoa;
    herr_t status = H5Fget_eoa(file_id, &eoa);
    if (status >= 0) {
        // Successfully retrieved EOA
    }
}

static void fuzz_H5Gget_num_objs(hid_t loc_id) {
    hsize_t num_objs;
    herr_t status = H5Gget_num_objs(loc_id, &num_objs);
    if (status >= 0) {
        // Successfully retrieved number of objects
    }
}

static void fuzz_H5Gget_info(hid_t loc_id) {
    H5G_info_t ginfo;
    herr_t status = H5Gget_info(loc_id, &ginfo);
    if (status >= 0) {
        // Successfully retrieved group info
    }
}

static void fuzz_H5Fget_obj_ids(hid_t file_id) {
    hid_t obj_id_list[10];
    ssize_t num_objs = H5Fget_obj_ids(file_id, H5F_OBJ_ALL, 10, obj_id_list);
    if (num_objs >= 0) {
        // Successfully retrieved object IDs
    }
}

static void fuzz_H5Glink2(hid_t cur_loc_id, hid_t new_loc_id) {
    herr_t status = H5Glink2(cur_loc_id, "existing_object", H5L_TYPE_HARD, new_loc_id, "new_link");
    if (status >= 0) {
        // Successfully created link
    }
}

static void fuzz_H5Dwrite(hid_t dset_id) {
    int data[10];
    herr_t status = H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
    if (status >= 0) {
        // Successfully wrote data
    }
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id >= 0) {
        fuzz_H5Fget_eoa(file_id);
        fuzz_H5Gget_num_objs(file_id);
        fuzz_H5Gget_info(file_id);
        fuzz_H5Fget_obj_ids(file_id);

        hid_t group_id = H5Gopen(file_id, "/", H5P_DEFAULT);
        if (group_id >= 0) {
            fuzz_H5Glink2(group_id, group_id);
            H5Gclose(group_id);
        }

        hid_t dset_id = H5Dopen(file_id, "dataset", H5P_DEFAULT);
        if (dset_id >= 0) {
            fuzz_H5Dwrite(dset_id);
            H5Dclose(dset_id);
        }

        H5Fclose(file_id);
    }

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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    