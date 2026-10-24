// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dwrite_multi at H5D.c:1419:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
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
#include <hdf5.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>

static void initialize_hdf5() {
    H5open();
}

static void finalize_hdf5() {
    H5close();
}

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create HDF5 file.\n");
        exit(EXIT_FAILURE);
    }
    return file_id;
}

static void create_dummy_dataset(hid_t loc_id, const char *name) {
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t dset_id = H5Dcreate2(loc_id, name, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        fprintf(stderr, "Failed to create dataset.\n");
        exit(EXIT_FAILURE);
    }
    H5Sclose(space_id);
    H5Dclose(dset_id);
}

static void write_dummy_data(hid_t dset_id) {
    int data = 42;
    if (H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, &data) < 0) {
        fprintf(stderr, "Failed to write data.\n");
        exit(EXIT_FAILURE);
    }
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    initialize_hdf5();

    hid_t file_id = create_dummy_file();
    create_dummy_dataset(file_id, "dataset1");
    create_dummy_dataset(file_id, "dataset2");

    hid_t dset_id1 = H5Dopen2(file_id, "dataset1", H5P_DEFAULT);
    hid_t dset_id2 = H5Dopen2(file_id, "dataset2", H5P_DEFAULT);

    if (dset_id1 < 0 || dset_id2 < 0) {
        fprintf(stderr, "Failed to open datasets.\n");
        H5Fclose(file_id);
        finalize_hdf5();
        return 0;
    }

    hid_t mem_type_id = H5Dget_type(dset_id1);
    if (mem_type_id < 0) {
        fprintf(stderr, "Failed to get datatype.\n");
        H5Dclose(dset_id1);
        H5Dclose(dset_id2);
        H5Fclose(file_id);
        finalize_hdf5();
        return 0;
    }

    hid_t mem_space_id = H5Screate(H5S_SCALAR);
    hid_t file_space_id = H5Screate(H5S_SCALAR);

    int buffer1 = 0, buffer2 = 0;
    const void *buffers[] = {&buffer1, &buffer2};
    hid_t dset_ids[] = {dset_id1, dset_id2};
    hid_t mem_type_ids[] = {mem_type_id, mem_type_id};
    hid_t mem_space_ids[] = {mem_space_id, mem_space_id};
    hid_t file_space_ids[] = {file_space_id, file_space_id};

    if (H5Dwrite_multi(2, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, H5P_DEFAULT, buffers) < 0) {
        fprintf(stderr, "H5Dwrite_multi failed.\n");
    }

    if (H5Dread(dset_id1, mem_type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, &buffer1) < 0) {
        fprintf(stderr, "Failed to read data.\n");
    }

    H5Sclose(mem_space_id);
    H5Sclose(file_space_id);
    H5Tclose(mem_type_id);
    H5Dclose(dset_id1);
    H5Dclose(dset_id2);
    H5Fclose(file_id);

    finalize_hdf5();
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
    