// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dget_create_plist at H5D.c:747:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
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
#include <stdlib.h>
#include <string.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>
#include <H5Ppublic.h>
#include <H5Fpublic.h>

static void create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id >= 0) {
        H5Fclose(file_id);
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    create_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    char group_name[256];
    if (Size < sizeof(group_name)) {
        memcpy(group_name, Data, Size);
        group_name[Size] = '\0';
    } else {
        memcpy(group_name, Data, sizeof(group_name) - 1);
        group_name[sizeof(group_name) - 1] = '\0';
    }

    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        hid_t gcpl_id = H5Gget_create_plist(group_id);
        if (gcpl_id >= 0) {
            H5Pclose(gcpl_id);
        }

        H5Gclose(group_id);
    }

    group_id = H5Gopen2(file_id, group_name, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    char dataset_name[256];
    snprintf(dataset_name, sizeof(dataset_name), "%s_dataset", group_name);

    hid_t space_id = H5Screate(H5S_SCALAR);
    if (space_id >= 0) {
        hid_t dset_id = H5Dcreate2(file_id, dataset_name, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        if (dset_id >= 0) {
            hid_t dcpl_id = H5Dget_create_plist(dset_id);
            if (dcpl_id >= 0) {
                H5Pclose(dcpl_id);
            }

            H5Dclose(dset_id);
        }

        dset_id = H5Dopen2(file_id, dataset_name, H5P_DEFAULT);
        if (dset_id >= 0) {
            H5Dclose(dset_id);
        }

        H5Sclose(space_id);
    }

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    