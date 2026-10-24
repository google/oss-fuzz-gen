// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
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
#include "H5Apublic.h"
#include "H5Dpublic.h"
#include "H5Gpublic.h"
#include "H5Ppublic.h"
#include "H5Spublic.h"
#include "H5Fpublic.h"
#include "H5Tpublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy data", file);
        fclose(file);
    }
}

static hid_t create_test_group(hid_t file_id) {
    return H5Gcreate2(file_id, "test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
}

static hid_t create_test_dataset(hid_t group_id) {
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t dset_id = H5Dcreate2(group_id, "test_dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);
    return dset_id;
}

static hid_t create_test_attribute(hid_t obj_id) {
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t attr_id = H5Acreate2(obj_id, "test_attribute", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);
    return attr_id;
}

int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    write_dummy_file();
    
    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t group_id = create_test_group(file_id);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t dset_id = create_test_dataset(group_id);
    if (dset_id < 0) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    hid_t attr_id = create_test_attribute(dset_id);
    if (attr_id < 0) {
        H5Dclose(dset_id);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    // Fuzz target functions with random inputs
    if (Size > 0) {
        char obj_name[256], attr_name[256];
        snprintf(obj_name, sizeof(obj_name), "%.*s", (int)(Size / 2), Data);
        snprintf(attr_name, sizeof(attr_name), "%.*s", (int)(Size / 2), Data + (Size / 2));

        hid_t test_attr_id = H5Aopen_by_name(group_id, obj_name, attr_name, H5P_DEFAULT, H5P_DEFAULT);
        if (test_attr_id >= 0) H5Aclose(test_attr_id);

        test_attr_id = H5Aopen_name(dset_id, attr_name);
        if (test_attr_id >= 0) H5Aclose(test_attr_id);
    }

    // Clean up
    H5Aclose(attr_id);
    H5Dclose(dset_id);
    H5Gclose(group_id);
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

        LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    