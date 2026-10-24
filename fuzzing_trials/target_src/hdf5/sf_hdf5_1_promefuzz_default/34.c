// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Fmount at H5F.c:1183:1 in H5Fpublic.h
// H5Funmount at H5F.c:1301:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Dpublic.h"
#include "H5Spublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"

#define FILE_NAME "./dummy_file"
#define DATASET_NAME "dset"

static hid_t create_file() {
    hid_t file_id = H5Fcreate(FILE_NAME, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create file\n");
    }
    return file_id;
}

static hid_t create_dataspace() {
    hsize_t dims[2] = {10, 10}; // Example dimensions
    hid_t space_id = H5Screate_simple(2, dims, NULL);
    if (space_id < 0) {
        fprintf(stderr, "Failed to create dataspace\n");
    }
    return space_id;
}

static hid_t create_datatype() {
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    if (type_id < 0) {
        fprintf(stderr, "Failed to create datatype\n");
    }
    return type_id;
}

static void close_resources(hid_t file_id, hid_t dset_id, hid_t space_id, hid_t type_id) {
    if (dset_id >= 0) H5Dclose(dset_id);
    if (space_id >= 0) H5Sclose(space_id);
    if (type_id >= 0) H5Tclose(type_id);
    if (file_id >= 0) H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    hid_t file_id = -1, dset_id = -1, space_id = -1, type_id = -1;
    H5G_info_t group_info;
    
    file_id = create_file();
    if (file_id < 0) return 0;

    space_id = create_dataspace();
    if (space_id < 0) {
        close_resources(file_id, dset_id, space_id, type_id);
        return 0;
    }

    type_id = create_datatype();
    if (type_id < 0) {
        close_resources(file_id, dset_id, space_id, type_id);
        return 0;
    }

    dset_id = H5Dcreate2(file_id, DATASET_NAME, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        fprintf(stderr, "Failed to create dataset\n");
    }

    // Try to open the dataset
    hid_t opened_dset_id = H5Dopen2(file_id, DATASET_NAME, H5P_DEFAULT);
    if (opened_dset_id < 0) {
        fprintf(stderr, "Failed to open dataset\n");
    } else {
        H5Dclose(opened_dset_id);
    }

    // Get group info
    if (H5Gget_info(file_id, &group_info) < 0) {
        fprintf(stderr, "Failed to get group info\n");
    }

    // Mount and unmount operations
    if (H5Fmount(file_id, "/", file_id, H5P_DEFAULT) < 0) {
        fprintf(stderr, "Failed to mount file\n");
    }

    if (H5Funmount(file_id, "/") < 0) {
        fprintf(stderr, "Failed to unmount file\n");
    }

    close_resources(file_id, dset_id, space_id, type_id);
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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    