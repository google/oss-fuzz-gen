// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Funmount at H5F.c:1301:1 in H5Fpublic.h
// H5Fmount at H5F.c:1183:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5public.h>
#include <H5Fpublic.h>
#include <H5Gpublic.h>
#include <H5Dpublic.h>
#include <H5Spublic.h>
#include <H5Tpublic.h>
#include <H5Ppublic.h>

static hid_t create_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static hid_t create_dataspace() {
    hsize_t dims[2] = {10, 10};
    hid_t space_id = H5Screate_simple(2, dims, NULL);
    return space_id;
}

static hid_t create_datatype() {
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    return type_id;
}

static void fuzz_H5Dcreate2(hid_t file_id, const uint8_t *Data, size_t Size) {
    char name[32];
    snprintf(name, sizeof(name), "dataset_%zu", Size);

    hid_t space_id = create_dataspace();
    hid_t type_id = create_datatype();
    hid_t dset_id = H5Dcreate2(file_id, name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    if (dset_id >= 0) {
        H5Dclose(dset_id);
    }

    H5Sclose(space_id);
    H5Tclose(type_id);
}

static void fuzz_H5Dopen2(hid_t file_id, const uint8_t *Data, size_t Size) {
    char name[32];
    snprintf(name, sizeof(name), "dataset_%zu", Size);

    hid_t dset_id = H5Dopen2(file_id, name, H5P_DEFAULT);
    if (dset_id >= 0) {
        H5Dclose(dset_id);
    }
}

static void fuzz_H5Gget_info(hid_t file_id) {
    H5G_info_t ginfo;
    H5Gget_info(file_id, &ginfo);
}

static void fuzz_H5Funmount(hid_t file_id, const uint8_t *Data, size_t Size) {
    char name[32];
    snprintf(name, sizeof(name), "mount_point_%zu", Size);
    H5Funmount(file_id, name);
}

static void fuzz_H5Fmount(hid_t file_id, const uint8_t *Data, size_t Size) {
    char name[32];
    snprintf(name, sizeof(name), "mount_point_%zu", Size);
    hid_t child_id = create_file();

    H5Fmount(file_id, name, child_id, H5P_DEFAULT);

    H5Fclose(child_id);
}

int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_file();

    fuzz_H5Dcreate2(file_id, Data, Size);
    fuzz_H5Dopen2(file_id, Data, Size);
    fuzz_H5Gget_info(file_id);
    fuzz_H5Funmount(file_id, Data, Size);
    fuzz_H5Fmount(file_id, Data, Size);

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

        LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    