// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Apublic.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>
#include <H5Fpublic.h>
#include <H5Tpublic.h>
#include <H5Spublic.h>
#include <H5Ppublic.h>

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void close_hid(hid_t id) {
    if (id >= 0) {
        H5Aclose(id);
    }
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0; // Not enough data

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0; // Failed to create file

    // Prepare strings from Data
    const char *name = (const char *)Data;
    const char *attr_name = (const char *)(Data + 1);

    // Fuzz H5Aopen_by_name
    hid_t attr_id = H5Aopen_by_name(file_id, name, attr_name, H5P_DEFAULT, H5P_DEFAULT);
    close_hid(attr_id);

    // Fuzz H5Acreate2
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    hid_t space_id = H5Screate(H5S_SCALAR);
    attr_id = H5Acreate2(file_id, attr_name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT);
    close_hid(attr_id);
    H5Tclose(type_id);
    H5Sclose(space_id);

    // Fuzz H5Aopen_name
    attr_id = H5Aopen_name(file_id, attr_name);
    close_hid(attr_id);

    // Fuzz H5Gcreate2
    hid_t group_id = H5Gcreate2(file_id, name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Fuzz H5Dcreate2
    type_id = H5Tcopy(H5T_NATIVE_INT);
    space_id = H5Screate(H5S_SCALAR);
    hid_t dataset_id = H5Dcreate2(file_id, name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }
    H5Tclose(type_id);
    H5Sclose(space_id);

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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    