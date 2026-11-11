// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dcreate_anon at H5D.c:273:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>
#include "H5Gpublic.h"
#include "H5Dpublic.h"

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return H5I_INVALID_HID;
    }
    return file_id;
}

static hid_t create_dummy_group(hid_t file_id, const char *group_name) {
    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        return H5I_INVALID_HID;
    }
    return group_id;
}

static hid_t create_dummy_dataset(hid_t file_id) {
    hsize_t dims[2] = {10, 10};
    hid_t dataspace_id = H5Screate_simple(2, dims, NULL);
    if (dataspace_id < 0) {
        return H5I_INVALID_HID;
    }
    hid_t dataset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, dataspace_id, 
                                  H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(dataspace_id);
    return dataset_id;
}

int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    if (file_id == H5I_INVALID_HID) {
        return 0;
    }

    hid_t group_id = create_dummy_group(file_id, "group");
    if (group_id == H5I_INVALID_HID) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t plist_id = H5Gget_create_plist(group_id);
    if (plist_id != H5I_INVALID_HID) {
        H5Pclose(plist_id);
    }

    hid_t opened_group_id = H5Gopen2(file_id, "group", H5P_DEFAULT);
    if (opened_group_id != H5I_INVALID_HID) {
        H5Gclose(opened_group_id);
    }

    herr_t link_status = H5Glink2(file_id, "group", H5L_TYPE_HARD, file_id, "linked_group");
    (void)link_status; // Ignoring the return value for fuzzing purposes

    hid_t dataset_id = create_dummy_dataset(file_id);
    if (dataset_id != H5I_INVALID_HID) {
        H5Dclose(dataset_id);
    }

    hid_t anon_dataset_id = H5Dcreate_anon(file_id, H5T_NATIVE_INT, H5Screate(H5S_SCALAR), 
                                           H5P_DEFAULT, H5P_DEFAULT);
    if (anon_dataset_id != H5I_INVALID_HID) {
        H5Dclose(anon_dataset_id);
    }

    H5Gclose(group_id);
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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    