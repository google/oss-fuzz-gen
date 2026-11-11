// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
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
#include <hdf5.h>
#include "H5Apublic.h"
#include "H5Dpublic.h"
#include "H5Gpublic.h"

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file\n");
        exit(1);
    }
    return file_id;
}

int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_dummy_file();
    herr_t status;

    // Fuzz H5Glink2
    const char *cur_name = "existing_object";
    const char *new_name = "new_link";
    H5G_link_t link_type = (H5G_link_t)(Data[0] % 2);  // Hard or soft link
    status = H5Glink2(file_id, cur_name, link_type, file_id, new_name);
    if (status < 0) {
        fprintf(stderr, "H5Glink2 failed\n");
    }

    // Fuzz H5Aopen_by_name
    const char *obj_name = "object";
    const char *attr_name = "attribute";
    hid_t attr_id = H5Aopen_by_name(file_id, obj_name, attr_name, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id < 0) {
        fprintf(stderr, "H5Aopen_by_name failed\n");
    } else {
        H5Aclose(attr_id);
    }

    // Fuzz H5Acreate2
    hid_t type_id = H5T_NATIVE_INT;
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t acpl_id = H5P_DEFAULT;
    hid_t aapl_id = H5P_DEFAULT;
    attr_id = H5Acreate2(file_id, attr_name, type_id, space_id, acpl_id, aapl_id);
    if (attr_id < 0) {
        fprintf(stderr, "H5Acreate2 failed\n");
    } else {
        H5Aclose(attr_id);
    }
    H5Sclose(space_id);

    // Fuzz H5Aopen_name
    attr_id = H5Aopen_name(file_id, attr_name);
    if (attr_id < 0) {
        fprintf(stderr, "H5Aopen_name failed\n");
    } else {
        H5Aclose(attr_id);
    }

    // Fuzz H5Gcreate2
    const char *group_name = "new_group";
    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        fprintf(stderr, "H5Gcreate2 failed\n");
    } else {
        H5Gclose(group_id);
    }

    // Fuzz H5Dcreate2
    const char *dataset_name = "new_dataset";
    space_id = H5Screate(H5S_SCALAR);
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) {
        fprintf(stderr, "H5Dcreate2 failed\n");
    } else {
        H5Dclose(dataset_id);
    }
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

        LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    