// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fmount at H5F.c:1183:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Funmount at H5F.c:1301:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void fuzz_H5Dcreate2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);

    char name[256];
    snprintf(name, sizeof(name), "dataset_%d", Data[0]);

    hid_t dataset_id = H5Dcreate2(file_id, name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    H5Sclose(space_id);
    H5Tclose(type_id);
    H5Fclose(file_id);
}

static void fuzz_H5Dopen2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);

    char name[256];
    snprintf(name, sizeof(name), "dataset_%d", Data[0]);

    hid_t dataset_id = H5Dcreate2(file_id, name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    hid_t opened_dataset_id = H5Dopen2(file_id, name, H5P_DEFAULT);
    if (opened_dataset_id >= 0) {
        H5Dclose(opened_dataset_id);
    }

    H5Sclose(space_id);
    H5Tclose(type_id);
    H5Fclose(file_id);
}

static void fuzz_H5Gget_info(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    H5G_info_t ginfo;
    H5Gget_info(file_id, &ginfo);

    H5Fclose(file_id);
}

static void fuzz_H5Funmount(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    char name[256];
    snprintf(name, sizeof(name), "mount_point_%d", Data[0]);

    H5Funmount(file_id, name);

    H5Fclose(file_id);
}

static void fuzz_H5Fmount(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return;

    hid_t child_file_id = create_dummy_file();
    if (child_file_id < 0) {
        H5Fclose(file_id);
        return;
    }

    char name[256];
    snprintf(name, sizeof(name), "mount_point_%d", Data[0]);

    H5Fmount(file_id, name, child_file_id, H5P_DEFAULT);

    H5Fclose(child_file_id);
    H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    fuzz_H5Dcreate2(Data, Size);
    fuzz_H5Dopen2(Data, Size);
    fuzz_H5Gget_info(Data, Size);
    fuzz_H5Funmount(Data, Size);
    fuzz_H5Fmount(Data, Size);
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

        LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    