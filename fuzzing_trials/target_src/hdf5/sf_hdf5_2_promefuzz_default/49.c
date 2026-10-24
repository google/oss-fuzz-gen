// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Dcreate_anon at H5D.c:273:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Gpublic.h>
#include <H5Dpublic.h>
#include <H5Fpublic.h>
#include <H5Ppublic.h>
#include <H5Tpublic.h>
#include <H5Spublic.h>
#include <H5Lpublic.h>

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void fuzz_H5Gget_create_plist(hid_t group_id) {
    hid_t plist_id = H5Gget_create_plist(group_id);
    if (plist_id >= 0) {
        H5Pclose(plist_id);
    }
}

static void fuzz_H5Gopen2(hid_t loc_id, const char *name, hid_t gapl_id) {
    hid_t group_id = H5Gopen2(loc_id, name, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Glink2(hid_t cur_loc_id, const char *cur_name, H5L_type_t type, hid_t new_loc_id, const char *new_name) {
    H5Glink2(cur_loc_id, cur_name, type, new_loc_id, new_name);
}

static void fuzz_H5Dcreate_anon(hid_t loc_id, hid_t type_id, hid_t space_id, hid_t dcpl_id, hid_t dapl_id) {
    hid_t dataset_id = H5Dcreate_anon(loc_id, type_id, space_id, dcpl_id, dapl_id);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
}

static void fuzz_H5Gcreate2(hid_t loc_id, const char *name, hid_t lcpl_id, hid_t gcpl_id, hid_t gapl_id) {
    hid_t group_id = H5Gcreate2(loc_id, name, lcpl_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Dcreate2(hid_t loc_id, const char *name, hid_t type_id, hid_t space_id, hid_t lcpl_id, hid_t dcpl_id, hid_t dapl_id) {
    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
}

int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0;

    // Fuzz H5Gget_create_plist
    fuzz_H5Gget_create_plist(file_id);

    // Fuzz H5Gopen2
    fuzz_H5Gopen2(file_id, "group_name", H5P_DEFAULT);

    // Fuzz H5Glink2
    fuzz_H5Glink2(file_id, "cur_name", H5L_TYPE_HARD, file_id, "new_name");

    // Fuzz H5Dcreate_anon
    fuzz_H5Dcreate_anon(file_id, H5T_NATIVE_INT, H5S_SCALAR, H5P_DEFAULT, H5P_DEFAULT);

    // Fuzz H5Gcreate2
    fuzz_H5Gcreate2(file_id, "new_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    // Fuzz H5Dcreate2
    fuzz_H5Dcreate2(file_id, "new_dataset", H5T_NATIVE_INT, H5S_SCALAR, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

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

        LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    