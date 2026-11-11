// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fget_freespace at H5F.c:1617:1 in H5Fpublic.h
// H5Fget_free_sections at H5F.c:2147:1 in H5Fpublic.h
// H5Fget_free_sections at H5F.c:2147:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Dpublic.h"
#include "H5Fpublic.h"
#include "H5Spublic.h"
#include "H5Tpublic.h"
#include "H5Ppublic.h"

// Create a simple dataspace
static hid_t create_dataspace() {
    hsize_t dims[1] = {10};
    return H5Screate_simple(1, dims, NULL);
}

// Create a datatype
static hid_t create_datatype() {
    return H5Tcopy(H5T_NATIVE_INT);
}

int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    const char *filename = "./dummy_file";
    hid_t file_id, dataset_id;
    herr_t status;
    hid_t space_id = create_dataspace();
    hid_t type_id = create_datatype();

    // Create a new file
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) goto cleanup;

    // Create and close a dataset
    dataset_id = H5Dcreate2(file_id, "dset", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    // Create and close another dataset
    dataset_id = H5Dcreate2(file_id, "dset2", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    // Close the file
    H5Fclose(file_id);

    // Open the file
    file_id = H5Fopen(filename, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) goto cleanup;

    // Get free space
    hssize_t free_space = H5Fget_freespace(file_id);

    // Get free sections
    for (int i = 0; i < 10; i++) {
        ssize_t nsects = H5Fget_free_sections(file_id, H5FD_MEM_DEFAULT, 0, NULL);
        if (nsects > 0) {
            H5F_sect_info_t *sect_info = (H5F_sect_info_t *)malloc(nsects * sizeof(H5F_sect_info_t));
            if (sect_info) {
                H5Fget_free_sections(file_id, H5FD_MEM_DEFAULT, nsects, sect_info);
                free(sect_info);
            }
        }
    }

    // Close the file
    H5Fclose(file_id);

cleanup:
    if (space_id >= 0) H5Sclose(space_id);
    if (type_id >= 0) H5Tclose(type_id);
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
    