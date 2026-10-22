// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fget_obj_ids at H5F.c:333:1 in H5Fpublic.h
// H5Fget_freespace at H5F.c:1617:1 in H5Fpublic.h
// H5Fget_intent at H5F.c:1540:1 in H5Fpublic.h
// H5Fget_create_plist at H5F.c:106:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Freopen at H5F.c:1440:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <H5Fpublic.h>
#include <H5Dpublic.h>
#include <H5Tpublic.h>
#include <H5Spublic.h>
#include <H5Ppublic.h>

static void fuzz_H5Fget_obj_ids(hid_t file_id) {
    unsigned types = H5F_OBJ_ALL;
    size_t max_objs = 10;
    hid_t obj_id_list[10];

    H5Fget_obj_ids(file_id, types, max_objs, obj_id_list);
}

static void fuzz_H5Fget_freespace(hid_t file_id) {
    H5Fget_freespace(file_id);
}

static void fuzz_H5Fget_intent(hid_t file_id) {
    unsigned intent;
    H5Fget_intent(file_id, &intent);
}

static void fuzz_H5Fget_create_plist(hid_t file_id) {
    hid_t plist_id = H5Fget_create_plist(file_id);
    if (plist_id >= 0) {
        H5Pclose(plist_id);
    }
}

static void fuzz_H5Dcreate2(hid_t loc_id) {
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t dataset_id = H5Dcreate2(loc_id, "dataset", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Tclose(type_id);
    H5Sclose(space_id);
}

static void fuzz_H5Freopen(hid_t file_id) {
    hid_t new_file_id = H5Freopen(file_id);
    if (new_file_id >= 0) {
        H5Fclose(new_file_id);
    }
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t)) {
        return 0;
    }

    hid_t file_id = *(hid_t *)Data;

    fuzz_H5Fget_obj_ids(file_id);
    fuzz_H5Fget_freespace(file_id);
    fuzz_H5Fget_intent(file_id);
    fuzz_H5Fget_create_plist(file_id);
    fuzz_H5Dcreate2(file_id);
    fuzz_H5Freopen(file_id);

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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    