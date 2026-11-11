// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
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

static void fuzz_H5Aopen_by_name(hid_t loc_id, const char *obj_name, const char *attr_name) {
    hid_t attr_id = H5Aopen_by_name(loc_id, obj_name, attr_name, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }
}

static void fuzz_H5Acreate2(hid_t loc_id, const char *attr_name) {
    hid_t type_id = H5T_NATIVE_INT;
    hid_t space_id = H5Screate(H5S_SCALAR);
    if (space_id >= 0) {
        hid_t attr_id = H5Acreate2(loc_id, attr_name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT);
        if (attr_id >= 0) {
            H5Aclose(attr_id);
        }
        H5Sclose(space_id);
    }
}

static void fuzz_H5Aopen_name(hid_t loc_id, const char *name) {
    hid_t attr_id = H5Aopen_name(loc_id, name);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }
}

static void fuzz_H5Dclose(hid_t dset_id) {
    H5Dclose(dset_id);
}

static void fuzz_H5Gcreate2(hid_t loc_id, const char *name) {
    hid_t group_id = H5Gcreate2(loc_id, name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Dcreate2(hid_t loc_id, const char *name) {
    hid_t type_id = H5T_NATIVE_INT;
    hid_t space_id = H5Screate(H5S_SCALAR);
    if (space_id >= 0) {
        hid_t dset_id = H5Dcreate2(loc_id, name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        if (dset_id >= 0) {
            H5Dclose(dset_id);
        }
        H5Sclose(space_id);
    }
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    char obj_name[256];
    char attr_name[256];
    char group_name[256];
    char dataset_name[256];

    snprintf(obj_name, sizeof(obj_name), "object_%02x", Data[0]);
    snprintf(attr_name, sizeof(attr_name), "attribute_%02x", Data[1]);
    snprintf(group_name, sizeof(group_name), "group_%02x", Data[0]);
    snprintf(dataset_name, sizeof(dataset_name), "dataset_%02x", Data[1]);

    fuzz_H5Aopen_by_name(file_id, obj_name, attr_name);
    fuzz_H5Acreate2(file_id, attr_name);
    fuzz_H5Aopen_name(file_id, attr_name);
    fuzz_H5Gcreate2(file_id, group_name);
    fuzz_H5Dcreate2(file_id, dataset_name);

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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    