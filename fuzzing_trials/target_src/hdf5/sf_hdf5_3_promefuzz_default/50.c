// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Awrite at H5A.c:908:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
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
#include <H5Apublic.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>
#include <H5Ppublic.h>
#include <H5Tpublic.h>
#include <H5Spublic.h>

static void create_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite("HDF5", 1, 4, file); // Write a simple HDF5 file signature
        fclose(file);
    }
}

static hid_t open_or_create_group(hid_t loc_id, const char *name) {
    hid_t group_id = H5Gcreate2(loc_id, name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        group_id = H5Gopen2(loc_id, name, H5P_DEFAULT);
    }
    return group_id;
}

int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    if (Size < 10) return 0; // Ensure there is enough data

    create_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    char obj_name[5];
    memcpy(obj_name, Data, 4);
    obj_name[4] = '\0';

    char attr_name[5];
    memcpy(attr_name, Data + 4, 4);
    attr_name[4] = '\0';

    hid_t group_id = open_or_create_group(file_id, obj_name);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    hid_t attr_id = H5Acreate2(group_id, attr_name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        int data = 42;
        H5Awrite(attr_id, type_id, &data);
        H5Aclose(attr_id);
    }

    attr_id = H5Aopen_by_name(group_id, obj_name, attr_name, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    attr_id = H5Aopen_name(group_id, attr_name);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    H5Sclose(space_id);
    H5Tclose(type_id);
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

        LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    