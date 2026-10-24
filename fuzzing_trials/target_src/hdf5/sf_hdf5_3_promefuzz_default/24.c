// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate_anon at H5D.c:273:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Dpublic.h"
#include "H5Gpublic.h"
#include "H5Fpublic.h"
#include "H5Ppublic.h"
#include "H5Spublic.h"
#include "H5Tpublic.h"

static hid_t create_hdf5_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void close_hdf5_file(hid_t file_id) {
    H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_hdf5_file();
    if (file_id < 0) return 0;

    char group_name[256];
    size_t name_len = (Size < 255) ? Size : 255;
    memcpy(group_name, Data, name_len);
    group_name[name_len] = '\0';

    // Fuzz H5Gcreate2
    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        // Fuzz H5Gget_info_by_name
        H5G_info_t ginfo;
        H5Gget_info_by_name(file_id, group_name, &ginfo, H5P_DEFAULT);

        // Fuzz H5Gflush
        H5Gflush(group_id);

        // Fuzz H5Gopen2
        hid_t open_group_id = H5Gopen2(file_id, group_name, H5P_DEFAULT);
        if (open_group_id >= 0) {
            H5Gclose(open_group_id);
        }

        // Fuzz H5Gcreate_anon
        hid_t anon_group_id = H5Gcreate_anon(file_id, H5P_DEFAULT, H5P_DEFAULT);
        if (anon_group_id >= 0) {
            H5Gclose(anon_group_id);
        }

        H5Gclose(group_id);
    }

    // Fuzz H5Dcreate_anon
    hid_t dataspace_id = H5Screate(H5S_SCALAR);
    hid_t dataset_id = H5Dcreate_anon(file_id, H5T_NATIVE_INT, dataspace_id, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Sclose(dataspace_id);

    close_hdf5_file(file_id);
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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    