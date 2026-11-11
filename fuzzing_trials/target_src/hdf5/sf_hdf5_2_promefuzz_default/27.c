// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dset_extent at H5D.c:1991:1 in H5Dpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dflush at H5D.c:2055:1 in H5Dpublic.h
// H5Dget_create_plist at H5D.c:747:1 in H5Dpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <H5Gpublic.h>
#include <H5Dpublic.h>
#include <H5Ppublic.h>
#include <H5Spublic.h>

#define DUMMY_FILE "./dummy_file"
#define DATASET_NAME "test_dataset"
#define GROUP_NAME "test_group"

static hid_t create_test_file() {
    hid_t file_id = H5Fcreate(DUMMY_FILE, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create test file\n");
        return -1;
    }
    return file_id;
}

static hid_t create_test_group(hid_t file_id) {
    hid_t group_id = H5Gcreate2(file_id, GROUP_NAME, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        fprintf(stderr, "Failed to create test group\n");
        return -1;
    }
    return group_id;
}

static hid_t create_test_dataset(hid_t group_id) {
    hsize_t dims[1] = {10};
    hid_t space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) {
        fprintf(stderr, "Failed to create dataspace\n");
        return -1;
    }

    hid_t dset_id = H5Dcreate2(group_id, DATASET_NAME, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);
    if (dset_id < 0) {
        fprintf(stderr, "Failed to create dataset\n");
        return -1;
    }
    return dset_id;
}

int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hsize_t)) return 0;

    hid_t file_id = create_test_file();
    if (file_id < 0) return 0;

    hid_t group_id = create_test_group(file_id);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t dset_id = create_test_dataset(group_id);
    if (dset_id < 0) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Fuzz H5Dset_extent
    hsize_t new_size[1];
    memcpy(new_size, Data, sizeof(hsize_t));
    H5Dset_extent(dset_id, new_size);

    // Fuzz H5Gopen2
    hid_t opened_group_id = H5Gopen2(file_id, GROUP_NAME, H5P_DEFAULT);
    if (opened_group_id >= 0) {
        H5Gclose(opened_group_id);
    }

    // Fuzz H5Dflush
    H5Dflush(dset_id);

    // Fuzz H5Dget_create_plist
    hid_t plist_id = H5Dget_create_plist(dset_id);
    if (plist_id >= 0) {
        H5Pclose(plist_id);
    }

    // Fuzz H5Dget_type
    hid_t dtype_id = H5Dget_type(dset_id);
    if (dtype_id >= 0) {
        H5Tclose(dtype_id);
    }

    H5Dclose(dset_id);
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
    