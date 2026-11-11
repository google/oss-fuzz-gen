// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_obj_count at H5F.c:216:1 in H5Fpublic.h
// H5Fget_obj_ids at H5F.c:333:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_obj_count at H5F.c:216:1 in H5Fpublic.h
// H5Fget_obj_ids at H5F.c:333:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Fpublic.h"
#include "H5Dpublic.h"
#include "H5Gpublic.h"
#include "H5Ppublic.h"
#include "H5Spublic.h"

#define MAX_OBJS 10

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy data", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    hid_t file_id, group_id, dataset_id, reopened_file_id, reopened_dataset_id;
    herr_t status;
    ssize_t obj_count;
    hid_t obj_ids[MAX_OBJS];

    // Create a file
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a group
    group_id = H5Gcreate2(file_id, "group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create a dataset
    hid_t space_id = H5Screate(H5S_SCALAR);
    dataset_id = H5Dcreate2(group_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);
    if (dataset_id < 0) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Get object count and IDs
    obj_count = H5Fget_obj_count(file_id, H5F_OBJ_ALL);
    if (obj_count > 0) {
        H5Fget_obj_ids(file_id, H5F_OBJ_ALL, MAX_OBJS, obj_ids);
    }

    // Close dataset and group
    H5Dclose(dataset_id);
    H5Gclose(group_id);

    // Close file
    H5Fclose(file_id);

    // Reopen file
    reopened_file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (reopened_file_id < 0) return 0;

    // Reopen dataset
    reopened_dataset_id = H5Dopen2(reopened_file_id, "/group/dataset", H5P_DEFAULT);
    if (reopened_dataset_id < 0) {
        H5Fclose(reopened_file_id);
        return 0;
    }

    // Close reopened dataset and file
    H5Dclose(reopened_dataset_id);
    H5Fclose(reopened_file_id);

    // Get object count and IDs again
    obj_count = H5Fget_obj_count(reopened_file_id, H5F_OBJ_ALL);
    if (obj_count > 0) {
        H5Fget_obj_ids(reopened_file_id, H5F_OBJ_ALL, MAX_OBJS, obj_ids);
    }

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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    