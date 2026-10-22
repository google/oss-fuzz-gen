// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
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
#include <stdio.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Dpublic.h"
#include "H5Ppublic.h"
#include "H5Spublic.h"
#include "H5Tpublic.h"

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file\n");
    }
    return file_id;
}

static void close_file(hid_t file_id) {
    if (file_id >= 0) {
        H5Fclose(file_id);
    }
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    hid_t file_id = create_dummy_file();
    if (file_id < 0) {
        return 0;
    }

    unsigned types = Data[0];
    size_t max_objs = 10;
    hid_t obj_id_list[10];

    // Fuzz H5Fget_obj_ids
    ssize_t num_objs = H5Fget_obj_ids(file_id, types, max_objs, obj_id_list);
    if (num_objs < 0) {
        fprintf(stderr, "H5Fget_obj_ids failed\n");
    }

    // Fuzz H5Fget_freespace
    hssize_t free_space = H5Fget_freespace(file_id);
    if (free_space < 0) {
        fprintf(stderr, "H5Fget_freespace failed\n");
    }

    // Fuzz H5Fget_intent
    unsigned intent;
    herr_t status = H5Fget_intent(file_id, &intent);
    if (status < 0) {
        fprintf(stderr, "H5Fget_intent failed\n");
    }

    // Fuzz H5Fget_create_plist
    hid_t plist_id = H5Fget_create_plist(file_id);
    if (plist_id < 0) {
        fprintf(stderr, "H5Fget_create_plist failed\n");
    } else {
        H5Pclose(plist_id);
    }

    // Fuzz H5Dcreate2
    hid_t space_id = H5Screate(H5S_SCALAR);
    if (space_id >= 0) {
        hid_t dset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        if (dset_id < 0) {
            fprintf(stderr, "H5Dcreate2 failed\n");
        } else {
            H5Dclose(dset_id);
        }
        H5Sclose(space_id);
    } else {
        fprintf(stderr, "Failed to create dataspace\n");
    }

    // Fuzz H5Freopen
    hid_t new_file_id = H5Freopen(file_id);
    if (new_file_id < 0) {
        fprintf(stderr, "H5Freopen failed\n");
    } else {
        H5Fclose(new_file_id);
    }

    close_file(file_id);
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
    