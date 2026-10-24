// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate1 at H5Gdeprec.c:153:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gopen1 at H5Gdeprec.c:247:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Dopen1 at H5Ddeprec.c:166:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>
#include <H5Ppublic.h>
#include <H5Fpublic.h>
#include <H5Ipublic.h>

static void handle_h5_error(hid_t id) {
    if (id == H5I_INVALID_HID) {
        // Handle error (e.g., log or abort)
    }
}

int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    handle_h5_error(file_id);

    char group_name[] = "test_group";
    char dataset_name[] = "test_dataset";

    // Fuzz H5Gcreate1
    hid_t group_id1 = H5Gcreate1(file_id, group_name, 0);
    handle_h5_error(group_id1);

    // Fuzz H5Gcreate2
    hid_t group_id2 = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    handle_h5_error(group_id2);

    // Fuzz H5Gopen1
    hid_t group_open_id1 = H5Gopen1(file_id, group_name);
    handle_h5_error(group_open_id1);

    // Fuzz H5Gopen2
    hid_t group_open_id2 = H5Gopen2(file_id, group_name, H5P_DEFAULT);
    handle_h5_error(group_open_id2);

    // Fuzz H5Gget_create_plist
    hid_t gcpl_id = H5Gget_create_plist(group_id2);
    handle_h5_error(gcpl_id);

    // Fuzz H5Dopen1
    hid_t dataset_id1 = H5Dopen1(file_id, dataset_name);
    handle_h5_error(dataset_id1);

    // Clean up
    if (group_id1 != H5I_INVALID_HID) H5Gclose(group_id1);
    if (group_id2 != H5I_INVALID_HID) H5Gclose(group_id2);
    if (group_open_id1 != H5I_INVALID_HID) H5Gclose(group_open_id1);
    if (group_open_id2 != H5I_INVALID_HID) H5Gclose(group_open_id2);
    if (gcpl_id != H5I_INVALID_HID) H5Pclose(gcpl_id);
    if (dataset_id1 != H5I_INVALID_HID) H5Dclose(dataset_id1);

    if (file_id != H5I_INVALID_HID) H5Fclose(file_id);

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

        LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    