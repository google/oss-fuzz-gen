// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Awrite at H5A.c:908:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aget_type at H5A.c:1128:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
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

#define DUMMY_FILE "./dummy_file"
#define DATASET_NAME "dataset"
#define ATTRIBUTE_NAME "attribute"
#define OBJECT_NAME "object"

static void write_dummy_file() {
    FILE *file = fopen(DUMMY_FILE, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    write_dummy_file();

    hid_t file_id1, file_id2, file_id3;
    hid_t attr_id, dataset_id, datatype_id;
    herr_t status;

    file_id1 = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id1 < 0) return 0;

    attr_id = H5Aopen_by_name(file_id1, OBJECT_NAME, ATTRIBUTE_NAME, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        status = H5Awrite(attr_id, H5T_NATIVE_INT, Data);
        status = H5Aclose(attr_id);
    }

    status = H5Fclose(file_id1);

    file_id2 = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id2 < 0) return 0;
    status = H5Fclose(file_id2);

    file_id3 = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id3 < 0) return 0;

    attr_id = H5Aopen_by_name(file_id3, OBJECT_NAME, ATTRIBUTE_NAME, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        datatype_id = H5Aget_type(attr_id);
        if (datatype_id >= 0) {
            status = H5Tclose(datatype_id);
        }
        status = H5Aclose(attr_id);
    }

    dataset_id = H5Dopen2(file_id3, DATASET_NAME, H5P_DEFAULT);
    if (dataset_id >= 0) {
        datatype_id = H5Dget_type(dataset_id);
        if (datatype_id >= 0) {
            status = H5Tclose(datatype_id);
        }
        status = H5Dclose(dataset_id);
    }

    status = H5Fclose(file_id3);

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
    