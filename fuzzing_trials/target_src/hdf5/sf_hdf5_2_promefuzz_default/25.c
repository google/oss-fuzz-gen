// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dset_extent at H5D.c:1991:1 in H5Dpublic.h
// H5Dflush at H5D.c:2055:1 in H5Dpublic.h
// H5Dget_create_plist at H5D.c:747:1 in H5Dpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Gpublic.h"
#include "H5Dpublic.h"
#include "H5Fpublic.h"
#include "H5Spublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"

static hid_t create_dummy_dataset() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return H5I_INVALID_HID;

    hsize_t dims[2] = {10, 10};
    hid_t space_id = H5Screate_simple(2, dims, NULL);
    if (space_id < 0) {
        H5Fclose(file_id);
        return H5I_INVALID_HID;
    }

    hid_t dset_id = H5Dcreate2(file_id, "dummy_dataset", H5T_NATIVE_INT, space_id,
                               H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);
    H5Fclose(file_id);
    return dset_id;
}

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hsize_t) * 2) return 0;

    hid_t dset_id = create_dummy_dataset();
    if (dset_id < 0) return 0;

    hsize_t new_dims[2];
    new_dims[0] = ((hsize_t *)Data)[0];
    new_dims[1] = ((hsize_t *)Data)[1];

    // Fuzz H5Dset_extent
    herr_t status = H5Dset_extent(dset_id, new_dims);
    if (status < 0) {
        fprintf(stderr, "H5Dset_extent failed\n");
    }

    // Fuzz H5Dflush
    status = H5Dflush(dset_id);
    if (status < 0) {
        fprintf(stderr, "H5Dflush failed\n");
    }

    // Fuzz H5Dget_create_plist
    hid_t plist_id = H5Dget_create_plist(dset_id);
    if (plist_id < 0) {
        fprintf(stderr, "H5Dget_create_plist failed\n");
    } else {
        H5Pclose(plist_id);
    }

    // Fuzz H5Dget_type
    hid_t type_id = H5Dget_type(dset_id);
    if (type_id < 0) {
        fprintf(stderr, "H5Dget_type failed\n");
    } else {
        H5Tclose(type_id);
    }

    // Fuzz H5Gopen2
    hid_t group_id = H5Gopen2(dset_id, "dummy_group", H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    H5Dclose(dset_id);
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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    