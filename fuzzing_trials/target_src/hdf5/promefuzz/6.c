// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Adelete_by_idx at H5A.c:2134:1 in H5Apublic.h
// H5Adelete_by_idx at H5A.c:2134:1 in H5Apublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Awrite at H5A.c:908:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Adelete_by_idx at H5A.c:2134:1 in H5Apublic.h
// H5Aget_info_by_idx at H5A.c:1501:1 in H5Apublic.h
// H5Aget_name_by_idx at H5A.c:1293:1 in H5Apublic.h
// H5Adelete_by_idx at H5A.c:2134:1 in H5Apublic.h
// H5Aget_info_by_idx at H5A.c:1501:1 in H5Apublic.h
// H5Aget_name_by_idx at H5A.c:1293:1 in H5Apublic.h
// H5Adelete_by_idx at H5A.c:2134:1 in H5Apublic.h
// H5Adelete_by_idx at H5A.c:2134:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "H5Dpublic.h"
#include "H5Fpublic.h"
#include "H5Apublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"

#define DUMMY_FILE "./dummy_file"

static void write_dummy_file() {
    FILE *file = fopen(DUMMY_FILE, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    hid_t file_id, dset_id, attr_id, type_id, space_id, acpl_id, aapl_id, lapl_id;
    H5_index_t idx_type = H5_INDEX_NAME;
    H5_iter_order_t order = H5_ITER_INC;
    H5A_info_t ainfo;
    char obj_name[256] = "dummy_object";
    char attr_name[256] = "dummy_attribute";
    char attr_name_out[256];
    hsize_t n = 0;
    size_t attr_name_size = sizeof(attr_name_out);
    herr_t status;

    write_dummy_file();

    file_id = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    dset_id = H5Dopen2(file_id, "dummy_dataset", H5P_DEFAULT);
    if (dset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    type_id = H5Tcopy(H5T_NATIVE_INT);
    space_id = H5Screate(H5S_SCALAR);
    acpl_id = H5P_DEFAULT;
    aapl_id = H5P_DEFAULT;
    lapl_id = H5P_DEFAULT;

    H5Adelete_by_idx(dset_id, obj_name, idx_type, order, n, lapl_id);
    H5Adelete_by_idx(dset_id, obj_name, idx_type, order, n, lapl_id);

    attr_id = H5Acreate2(dset_id, attr_name, type_id, space_id, acpl_id, aapl_id);
    if (attr_id >= 0) {
        int data = 42;
        H5Awrite(attr_id, type_id, &data);
        H5Aclose(attr_id);
    }

    H5Adelete_by_idx(dset_id, obj_name, idx_type, order, n, lapl_id);
    H5Aget_info_by_idx(dset_id, obj_name, idx_type, order, n, &ainfo, lapl_id);
    H5Aget_name_by_idx(dset_id, obj_name, idx_type, order, n, attr_name_out, attr_name_size, lapl_id);
    H5Adelete_by_idx(dset_id, obj_name, idx_type, order, n, lapl_id);
    H5Aget_info_by_idx(dset_id, obj_name, idx_type, order, n, &ainfo, lapl_id);
    H5Aget_name_by_idx(dset_id, obj_name, idx_type, order, n, attr_name_out, attr_name_size, lapl_id);
    H5Adelete_by_idx(dset_id, obj_name, idx_type, order, n, lapl_id);
    H5Adelete_by_idx(dset_id, obj_name, idx_type, order, n, lapl_id);

    H5Dclose(dset_id);
    H5Dclose(dset_id);
    H5Dclose(dset_id);

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

        LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    