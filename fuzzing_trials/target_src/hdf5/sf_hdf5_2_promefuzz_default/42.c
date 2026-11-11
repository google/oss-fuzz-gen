// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dget_create_plist at H5D.c:747:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
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
#include <stdlib.h>
#include <hdf5.h>
#include <H5Gpublic.h>
#include <H5Dpublic.h>

static void handle_error(hid_t id) {
    if (id < 0) {
        // Handle error, possibly log it
    }
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0; // Ensure there's enough data for basic operations

    // Create a dummy file
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Use part of the input data to create a group
    size_t name_len = Size / 2;
    char *group_name = (char *)malloc(name_len + 1);
    if (!group_name) {
        H5Fclose(file_id);
        return 0;
    }
    memcpy(group_name, Data, name_len);
    group_name[name_len] = '\0';

    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    handle_error(group_id);

    // Fuzzing H5Gget_create_plist
    hid_t gcpl_id = H5Gget_create_plist(group_id);
    handle_error(gcpl_id);
    if (gcpl_id >= 0) H5Pclose(gcpl_id);

    // Fuzzing H5Gopen2
    hid_t opened_group_id = H5Gopen2(file_id, group_name, H5P_DEFAULT);
    handle_error(opened_group_id);
    if (opened_group_id >= 0) H5Gclose(opened_group_id);

    // Use remaining data to create a dataset
    if (Size > name_len + 1) {
        size_t dset_name_len = Size - name_len - 1;
        char *dset_name = (char *)malloc(dset_name_len + 1);
        if (dset_name) {
            memcpy(dset_name, Data + name_len + 1, dset_name_len);
            dset_name[dset_name_len] = '\0';

            hid_t space_id = H5Screate(H5S_SCALAR);
            hid_t dset_id = H5Dcreate2(file_id, dset_name, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
            handle_error(dset_id);

            // Fuzzing H5Dget_create_plist
            hid_t dcpl_id = H5Dget_create_plist(dset_id);
            handle_error(dcpl_id);
            if (dcpl_id >= 0) H5Pclose(dcpl_id);

            // Fuzzing H5Dopen2
            hid_t opened_dset_id = H5Dopen2(file_id, dset_name, H5P_DEFAULT);
            handle_error(opened_dset_id);
            if (opened_dset_id >= 0) H5Dclose(opened_dset_id);

            if (dset_id >= 0) H5Dclose(dset_id);
            H5Sclose(space_id);
            free(dset_name);
        }
    }

    if (group_id >= 0) H5Gclose(group_id);
    H5Fclose(file_id);
    free(group_name);

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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    