// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Awrite at H5A.c:908:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Aget_info_by_name at H5A.c:1445:1 in H5Apublic.h
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
#include <stdlib.h>
#include <string.h>
#include "H5Dpublic.h"
#include "H5Fpublic.h"
#include "H5Apublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy data", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t attr_id = H5Acreate2(file_id, "attr_name", H5T_NATIVE_INT, H5S_SCALAR, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        int data = 42;
        H5Awrite(attr_id, H5T_NATIVE_INT, &data);
        H5Aclose(attr_id);
    }

    hid_t dset_id1 = H5Dopen2(file_id, "dataset1", H5P_DEFAULT);
    hid_t dset_id2 = H5Dopen2(file_id, "dataset2", H5P_DEFAULT);
    hid_t dset_id3 = H5Dopen2(file_id, "dataset3", H5P_DEFAULT);

    if (dset_id1 >= 0) H5Dclose(dset_id1);
    if (dset_id2 >= 0) H5Dclose(dset_id2);
    if (dset_id3 >= 0) H5Dclose(dset_id3);

    H5Fclose(file_id);

    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id >= 0) {
        dset_id1 = H5Dopen2(file_id, "dataset1", H5P_DEFAULT);
        dset_id2 = H5Dopen2(file_id, "dataset2", H5P_DEFAULT);
        dset_id3 = H5Dopen2(file_id, "dataset3", H5P_DEFAULT);

        H5A_info_t ainfo;
        H5Aget_info_by_name(file_id, "dataset1", "attr_name", &ainfo, H5P_DEFAULT);

        if (dset_id1 >= 0) H5Dclose(dset_id1);
        if (dset_id2 >= 0) H5Dclose(dset_id2);
        if (dset_id3 >= 0) H5Dclose(dset_id3);

        H5Fclose(file_id);
    }

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

        LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    