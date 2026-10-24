// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite_multi at H5D.c:1419:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
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

static void setup_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file\n");
        exit(EXIT_FAILURE);
    }
    H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    setup_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Fuzz H5Dcreate2
    {
        hid_t space_id = H5Screate(H5S_SCALAR);
        hid_t dset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        if (dset_id >= 0) {
            H5Dclose(dset_id);
        }
        H5Sclose(space_id);
    }

    // Fuzz H5Dopen2
    {
        hid_t dset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
        if (dset_id >= 0) {
            H5Dclose(dset_id);
        }
    }

    // Fuzz H5Dget_type
    {
        hid_t dset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
        if (dset_id >= 0) {
            hid_t type_id = H5Dget_type(dset_id);
            if (type_id >= 0) {
                H5Tclose(type_id);
            }
            H5Dclose(dset_id);
        }
    }

    // Fuzz H5Dwrite_multi
    {
        hid_t space_id = H5Screate(H5S_SCALAR);
        hid_t dset_id = H5Dcreate2(file_id, "dataset_multi", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        if (dset_id >= 0) {
            int data = 42;
            hid_t dset_ids[] = {dset_id};
            hid_t mem_type_ids[] = {H5T_NATIVE_INT};
            hid_t mem_space_ids[] = {H5S_ALL};
            hid_t file_space_ids[] = {H5S_ALL};
            const void *bufs[] = {&data};
            H5Dwrite_multi(1, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, H5P_DEFAULT, bufs);
            H5Dclose(dset_id);
        }
        H5Sclose(space_id);
    }

    // Fuzz H5Dread
    {
        hid_t dset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
        if (dset_id >= 0) {
            int data;
            H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, &data);
            H5Dclose(dset_id);
        }
    }

    // Fuzz H5Gcreate2
    {
        hid_t group_id = H5Gcreate2(file_id, "group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        if (group_id >= 0) {
            H5Gclose(group_id);
        }
    }

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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    