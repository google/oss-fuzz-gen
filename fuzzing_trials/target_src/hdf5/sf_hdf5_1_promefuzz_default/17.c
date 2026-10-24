// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fmount at H5F.c:1183:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Funmount at H5F.c:1301:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Dpublic.h"

static void initialize_hdf5_environment() {
    H5open();
}

static void cleanup_hdf5_environment() {
    H5close();
}

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void create_and_close_dataset(hid_t file_id, const char *name) {
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    hid_t dset_id = H5Dcreate2(file_id, name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id >= 0) {
        H5Dclose(dset_id);
    }
    H5Sclose(space_id);
    H5Tclose(type_id);
}

static void fuzz_H5Dcreate2(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    char *name = (char *)malloc(Size + 1);
    if (name == NULL) {
        H5Fclose(file_id);
        return;
    }
    memcpy(name, Data, Size);
    name[Size] = '\0';

    create_and_close_dataset(file_id, name);

    free(name);
    H5Fclose(file_id);
}

static void fuzz_H5Dopen2(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    char *name = (char *)malloc(Size + 1);
    if (name == NULL) {
        H5Fclose(file_id);
        return;
    }
    memcpy(name, Data, Size);
    name[Size] = '\0';

    hid_t dset_id = H5Dopen2(file_id, name, H5P_DEFAULT);
    if (dset_id >= 0) {
        H5Dclose(dset_id);
    }

    free(name);
    H5Fclose(file_id);
}

static void fuzz_H5Gget_info(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    H5G_info_t ginfo;
    H5Gget_info(file_id, &ginfo);

    H5Fclose(file_id);
}

static void fuzz_H5Funmount(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    char *name = (char *)malloc(Size + 1);
    if (name == NULL) {
        H5Fclose(file_id);
        return;
    }
    memcpy(name, Data, Size);
    name[Size] = '\0';

    H5Funmount(file_id, name);

    free(name);
    H5Fclose(file_id);
}

static void fuzz_H5Fmount(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    char *name = (char *)malloc(Size + 1);
    if (name == NULL) {
        H5Fclose(file_id);
        return;
    }
    memcpy(name, Data, Size);
    name[Size] = '\0';

    hid_t child_file_id = H5Fcreate("./dummy_child_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (child_file_id >= 0) {
        H5Fmount(file_id, name, child_file_id, H5P_DEFAULT);
        H5Fclose(child_file_id);
    }

    free(name);
    H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    initialize_hdf5_environment();

    fuzz_H5Dcreate2(Data, Size);
    fuzz_H5Dopen2(Data, Size);
    fuzz_H5Gget_info(Data, Size);
    fuzz_H5Funmount(Data, Size);
    fuzz_H5Fmount(Data, Size);

    cleanup_hdf5_environment();
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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    