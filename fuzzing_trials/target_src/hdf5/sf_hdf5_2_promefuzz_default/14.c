// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_freespace at H5F.c:1617:1 in H5Fpublic.h
// H5Fget_free_sections at H5F.c:2147:1 in H5Fpublic.h
// H5Fget_free_sections at H5F.c:2147:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <H5Fpublic.h>
#include <H5Dpublic.h>
#include <H5Ppublic.h>
#include <H5Spublic.h>
#include <H5Tpublic.h>

#define DUMMY_FILE "./dummy_file"
#define DATASET_NAME "dset"

static hid_t create_file() {
    return H5Fcreate(DUMMY_FILE, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
}

static hid_t open_file() {
    return H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
}

static hid_t create_dataset(hid_t file_id) {
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t dset_id = H5Dcreate2(file_id, DATASET_NAME, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);
    return dset_id;
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    hid_t file_id, dset_id;
    herr_t status;
    hssize_t free_space;
    ssize_t num_sections;
    H5F_sect_info_t *sect_info = NULL;

    // Create and close a file
    file_id = create_file();
    if (file_id >= 0) {
        status = H5Fclose(file_id);

        // Re-open the file
        file_id = open_file();
        if (file_id >= 0) {
            // Create and close a dataset
            dset_id = create_dataset(file_id);
            if (dset_id >= 0) {
                status = H5Dclose(dset_id);
            }

            // Create and close a dataset again
            dset_id = create_dataset(file_id);
            if (dset_id >= 0) {
                status = H5Dclose(dset_id);
            }

            // Close the file
            status = H5Fclose(file_id);
        }
    }

    // Re-open the file for free space queries
    file_id = open_file();
    if (file_id >= 0) {
        // Get free space
        free_space = H5Fget_freespace(file_id);

        // Get number of free space sections
        num_sections = H5Fget_free_sections(file_id, H5FD_MEM_DEFAULT, (size_t)0, NULL);
        if (num_sections > 0) {
            sect_info = (H5F_sect_info_t *)malloc(num_sections * sizeof(H5F_sect_info_t));
            if (sect_info) {
                num_sections = H5Fget_free_sections(file_id, H5FD_MEM_DEFAULT, (size_t)num_sections, sect_info);
                free(sect_info);
            }
        }

        // Close the file
        status = H5Fclose(file_id);
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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    