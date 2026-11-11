// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Apublic.h"
#include "H5Dpublic.h"
#include "H5Gpublic.h"
#include "H5Fpublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"
#include "H5Ppublic.h"

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file\n");
        exit(EXIT_FAILURE);
    }
    return file_id;
}

static void close_hid(hid_t id) {
    if (id >= 0) {
        H5Aclose(id);
    }
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_dummy_file();
    hid_t attr_id = -1;
    hid_t group_id = -1;
    hid_t dataset_id = -1;
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);

    char attr_name[Size];
    attr_name[0] = '\0';

    // Fuzz H5Gcreate2
    if (Size > 1) {
        char group_name[Size];
        memcpy(group_name, Data, Size - 1);
        group_name[Size - 1] = '\0';
        group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    }

    // Fuzz H5Dcreate2
    if (Size > 2) {
        char dataset_name[Size - 1];
        memcpy(dataset_name, Data + 1, Size - 2);
        dataset_name[Size - 2] = '\0';
        dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    }

    // Fuzz H5Acreate2
    if (Size > 3) {
        memcpy(attr_name, Data + 2, Size - 3);
        attr_name[Size - 3] = '\0';
        attr_id = H5Acreate2(file_id, attr_name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT);
    }

    // Fuzz H5Aopen_by_name
    if (Size > 4) {
        char obj_name[Size - 3];
        memcpy(obj_name, Data + 3, Size - 4);
        obj_name[Size - 4] = '\0';
        hid_t open_attr_id = H5Aopen_by_name(file_id, obj_name, attr_name, H5P_DEFAULT, H5P_DEFAULT);
        close_hid(open_attr_id);
    }

    // Fuzz H5Aopen_name
    if (Size > 5) {
        char open_attr_name[Size - 4];
        memcpy(open_attr_name, Data + 4, Size - 5);
        open_attr_name[Size - 5] = '\0';
        hid_t open_attr_id = H5Aopen_name(file_id, open_attr_name);
        close_hid(open_attr_id);
    }

    // Cleanup
    close_hid(attr_id);
    if (dataset_id >= 0) H5Dclose(dataset_id);
    if (group_id >= 0) H5Gclose(group_id);
    if (space_id >= 0) H5Sclose(space_id);
    if (type_id >= 0) H5Tclose(type_id);
    if (file_id >= 0) H5Fclose(file_id);

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

        LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    