// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fget_metadata_read_retry_info at H5F.c:2104:1 in H5Fpublic.h
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
#include "H5Ppublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        const char dummy_data[] = "HDF5 dummy data";
        fwrite(dummy_data, 1, sizeof(dummy_data), file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDONLY, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    hid_t dataset_id1 = H5Dopen2(file_id, "dataset1", H5P_DEFAULT);
    if (dataset_id1 >= 0) {
        char buffer1[128];
        H5Dread(dataset_id1, H5T_NATIVE_CHAR, H5S_ALL, H5S_ALL, H5P_DEFAULT, buffer1);
        H5Dclose(dataset_id1);
    }

    hid_t dataset_id2 = H5Dopen2(file_id, "dataset2", H5P_DEFAULT);
    if (dataset_id2 >= 0) {
        char buffer2[128];
        H5Dread(dataset_id2, H5T_NATIVE_CHAR, H5S_ALL, H5S_ALL, H5P_DEFAULT, buffer2);
        H5Dclose(dataset_id2);
    }

    H5F_retry_info_t retry_info;
    if (H5Fget_metadata_read_retry_info(file_id, &retry_info) >= 0) {
        for (unsigned i = 0; i < H5F_NUM_METADATA_READ_RETRY_TYPES; i++) {
            if (retry_info.retries[i]) {
                free(retry_info.retries[i]);
            }
        }
    }

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

        LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    