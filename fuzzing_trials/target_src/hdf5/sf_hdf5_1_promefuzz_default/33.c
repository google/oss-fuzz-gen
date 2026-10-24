// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fmount at H5F.c:1183:1 in H5Fpublic.h
// H5Funmount at H5F.c:1301:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hdf5.h"

static void create_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "Dummy HDF5 file content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare environment
    create_dummy_file();
    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Variables for dataset creation
    const char *dataset_name = "fuzz_dataset";
    hid_t dtype_id = H5T_NATIVE_INT;
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t dcpl_id = H5P_DEFAULT;
    hid_t dapl_id = H5P_DEFAULT;

    // Create dataset
    hid_t dset_id = H5Dcreate2(file_id, dataset_name, dtype_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dset_id >= 0) {
        // Open the dataset
        hid_t open_dset_id = H5Dopen2(file_id, dataset_name, dapl_id);
        if (open_dset_id >= 0) {
            // Retrieve group info
            H5G_info_t ginfo;
            if (H5Gget_info(file_id, &ginfo) >= 0) {
                // Use group info for further operations
            }
            H5Dclose(open_dset_id);
        }
        H5Dclose(dset_id);
    }

    // Mount and unmount operations
    hid_t child_file_id = H5Fcreate("child_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (child_file_id >= 0) {
        if (H5Fmount(file_id, "/mount_point", child_file_id, H5P_DEFAULT) >= 0) {
            H5Funmount(file_id, "/mount_point");
        }
        H5Fclose(child_file_id);
    }

    // Cleanup
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

        LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    