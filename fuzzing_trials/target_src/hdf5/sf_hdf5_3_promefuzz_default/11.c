// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite_multi at H5D.c:1419:1 in H5Dpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "H5Dpublic.h"
#include "H5Gpublic.h"
#include "H5Fpublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void cleanup(hid_t *ids, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (ids[i] >= 0) {
            H5Dclose(ids[i]);
        }
    }
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0;

    // Prepare dummy data for fuzzing
    size_t count = Data[0] % 10; // Limit the count to 10 for simplicity
    hid_t *dset_ids = (hid_t *)malloc(count * sizeof(hid_t));
    hid_t *mem_type_ids = (hid_t *)malloc(count * sizeof(hid_t));
    hid_t *mem_space_ids = (hid_t *)malloc(count * sizeof(hid_t));
    hid_t *file_space_ids = (hid_t *)malloc(count * sizeof(hid_t));
    const void **bufs = (const void **)malloc(count * sizeof(void *));

    if (!dset_ids || !mem_type_ids || !mem_space_ids || !file_space_ids || !bufs) {
        free(dset_ids);
        free(mem_type_ids);
        free(mem_space_ids);
        free(file_space_ids);
        free(bufs);
        H5Fclose(file_id);
        return 0;
    }

    // Initialize datasets and buffers
    for (size_t i = 0; i < count; i++) {
        char name[20];
        snprintf(name, sizeof(name), "dset_%zu", i);
        dset_ids[i] = H5Dcreate2(file_id, name, H5T_NATIVE_INT, H5Screate(H5S_SCALAR), H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        mem_type_ids[i] = H5T_NATIVE_INT;
        mem_space_ids[i] = H5Screate(H5S_SCALAR);
        file_space_ids[i] = H5Screate(H5S_SCALAR);
        bufs[i] = malloc(sizeof(int));
        if (bufs[i]) {
            *(int *)bufs[i] = (int)Data[i % Size];
        }
    }

    // Fuzz H5Dwrite_multi
    H5Dwrite_multi(count, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, H5P_DEFAULT, bufs);

    // Fuzz H5Dget_type
    for (size_t i = 0; i < count; i++) {
        if (dset_ids[i] >= 0) {
            hid_t type_id = H5Dget_type(dset_ids[i]);
            if (type_id >= 0) {
                H5Tclose(type_id);
            }
        }
    }

    // Fuzz H5Dread
    for (size_t i = 0; i < count; i++) {
        if (dset_ids[i] >= 0) {
            int read_buf;
            H5Dread(dset_ids[i], mem_type_ids[i], mem_space_ids[i], file_space_ids[i], H5P_DEFAULT, &read_buf);
        }
    }

    // Cleanup
    cleanup(dset_ids, count);
    free(dset_ids);
    free(mem_type_ids);
    free(mem_space_ids);
    free(file_space_ids);
    for (size_t i = 0; i < count; i++) {
        free((void *)bufs[i]);
    }
    free(bufs);
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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    