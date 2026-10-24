// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Diterate at H5D.c:1842:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dfill at H5D.c:1758:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "H5Fpublic.h"
#include "H5Dpublic.h"
#include "H5Apublic.h"
#include "H5Ppublic.h"
#include "H5Spublic.h"
#include "H5Tpublic.h"

static herr_t dummy_iterate(void *elem, hid_t type_id, hsize_t ndim, hssize_t *point, void *operator_data) {
    // Dummy iterate function for H5Diterate
    return 0;
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t space_id = H5Screate(H5S_SCALAR);
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    if (type_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    hid_t dset_id = H5Dcreate2(file_id, "dataset", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    int data = 0;
    herr_t status;

    for (int i = 0; i < 3; i++) {
        status = H5Dwrite(dset_id, type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, &data);
        if (status < 0) break;
    }

    status = H5Diterate(&data, type_id, space_id, dummy_iterate, NULL);
    if (status < 0) {
        H5Dclose(dset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    status = H5Dfill(&data, type_id, &data, type_id, space_id);
    if (status < 0) {
        H5Dclose(dset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    hid_t attr_id = H5Acreate2(dset_id, "attribute", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id < 0) {
        H5Dclose(dset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }
    H5Aclose(attr_id);

    for (int i = 0; i < 3; i++) {
        status = H5Dread(dset_id, type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, &data);
        if (status < 0) break;
    }

    H5Dclose(dset_id);
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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    