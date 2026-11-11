// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dread_multi at H5D.c:1109:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dwrite_multi at H5D.c:1419:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Dpublic.h"
#include "H5Fpublic.h"
#include "H5Spublic.h"
#include "H5Tpublic.h"
#include "H5Ppublic.h"

static hid_t create_dataspace() {
    hsize_t dims[1] = {10};
    return H5Screate_simple(1, dims, NULL);
}

static hid_t create_datatype() {
    return H5Tcopy(H5T_NATIVE_INT);
}

static void write_dummy_data(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    const char *filename = "./dummy_file";
    write_dummy_data(filename);

    hid_t file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t space_id = create_dataspace();
    hid_t type_id = create_datatype();

    hid_t dset_id1 = H5Dcreate2(file_id, "dataset1", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id1 < 0) goto cleanup_file;

    hid_t dset_id2 = H5Dcreate2(file_id, "dataset2", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id2 < 0) goto cleanup_dset1;

    if (H5Dclose(dset_id1) < 0) goto cleanup_dset2;

    hid_t dset_ids[] = {dset_id2};
    hid_t mem_type_ids[] = {type_id};
    hid_t mem_space_ids[] = {space_id};
    hid_t file_space_ids[] = {space_id};
    int buf[10] = {0};

    if (H5Dread_multi(1, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, H5P_DEFAULT, (void **)buf) < 0)
        goto cleanup_dset2;

    if (H5Dread(dset_id2, type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, buf) < 0)
        goto cleanup_dset2;

    if (H5Dwrite_multi(1, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, H5P_DEFAULT, (const void **)buf) < 0)
        goto cleanup_dset2;

    if (H5Dwrite(dset_id2, type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, buf) < 0)
        goto cleanup_dset2;

    if (H5Dclose(dset_id2) < 0) goto cleanup_file;

    if (H5Fclose(file_id) < 0) goto cleanup_file;

    if (H5Dclose(dset_id1) < 0) return 0;
    if (H5Fclose(file_id) < 0) return 0;

    H5Sclose(space_id);
    H5Tclose(type_id);
    return 0;

cleanup_dset2:
    H5Dclose(dset_id2);
cleanup_dset1:
    H5Dclose(dset_id1);
cleanup_file:
    H5Fclose(file_id);
    H5Sclose(space_id);
    H5Tclose(type_id);
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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    