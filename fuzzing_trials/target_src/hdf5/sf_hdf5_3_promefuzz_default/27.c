// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_create_plist at H5D.c:747:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
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
#include <hdf5.h>
#include "H5Dpublic.h"
#include "H5Gpublic.h"

static void handle_error(hid_t id) {
    if (id == H5I_INVALID_HID) {
        fprintf(stderr, "Error: Invalid HID\n");
    }
}

int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy file
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, "group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Call H5Gget_create_plist
    hid_t gcpl_id = H5Gget_create_plist(group_id);
    handle_error(gcpl_id);
    if (gcpl_id != H5I_INVALID_HID) {
        H5Pclose(gcpl_id);
    }

    // Call H5Gopen2
    hid_t open_group_id = H5Gopen2(file_id, "group", H5P_DEFAULT);
    handle_error(open_group_id);
    if (open_group_id != H5I_INVALID_HID) {
        H5Gclose(open_group_id);
    }

    // Call H5Gcreate2 with fuzzed data as name
    char group_name[256];
    snprintf(group_name, sizeof(group_name), "%.*s", (int)Size, Data);
    hid_t fuzz_group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    handle_error(fuzz_group_id);
    if (fuzz_group_id != H5I_INVALID_HID) {
        H5Gclose(fuzz_group_id);
    }

    // Create a dataset in the group
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t dataset_id = H5Dcreate2(group_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) {
        H5Sclose(space_id);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Call H5Dget_create_plist
    hid_t dcpl_id = H5Dget_create_plist(dataset_id);
    handle_error(dcpl_id);
    if (dcpl_id != H5I_INVALID_HID) {
        H5Pclose(dcpl_id);
    }

    // Call H5Dopen2
    hid_t open_dataset_id = H5Dopen2(group_id, "dataset", H5P_DEFAULT);
    handle_error(open_dataset_id);
    if (open_dataset_id != H5I_INVALID_HID) {
        H5Dclose(open_dataset_id);
    }

    // Call H5Dcreate2 with fuzzed data as name
    char dataset_name[256];
    snprintf(dataset_name, sizeof(dataset_name), "%.*s", (int)Size, Data);
    hid_t fuzz_dataset_id = H5Dcreate2(group_id, dataset_name, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    handle_error(fuzz_dataset_id);
    if (fuzz_dataset_id != H5I_INVALID_HID) {
        H5Dclose(fuzz_dataset_id);
    }

    // Cleanup
    H5Dclose(dataset_id);
    H5Sclose(space_id);
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

        LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    