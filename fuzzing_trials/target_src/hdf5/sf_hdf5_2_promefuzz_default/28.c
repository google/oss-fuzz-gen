// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Acreate1 at H5Adeprec.c:103:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Dcreate1 at H5Ddeprec.c:98:1 in H5Dpublic.h
// H5Aget_num_attrs at H5Adeprec.c:303:1 in H5Apublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Dpublic.h"
#include "H5Apublic.h"
#include "H5Fpublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"
#include "H5Ppublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        const char *data = "dummy data";
        fwrite(data, 1, strlen(data), file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    hid_t space_id = H5Screate(H5S_SCALAR);
    if (type_id >= 0 && space_id >= 0) {
        H5Acreate1(file_id, (const char *)Data, type_id, space_id, H5P_DEFAULT);
    }

    H5Aopen_name(file_id, (const char *)Data);

    H5Dcreate1(file_id, (const char *)Data, type_id, space_id, H5P_DEFAULT);

    H5Aget_num_attrs(file_id);

    H5Dcreate2(file_id, (const char *)Data, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    H5Aopen_by_name(file_id, ".", (const char *)Data, H5P_DEFAULT, H5P_DEFAULT);

    if (type_id >= 0) H5Tclose(type_id);
    if (space_id >= 0) H5Sclose(space_id);
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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    