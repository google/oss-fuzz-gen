// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite_multi at H5D.c:1419:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>

static void create_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

static herr_t write_multi_datasets(hid_t file_id, size_t count) {
    hid_t *dset_ids = (hid_t *)malloc(count * sizeof(hid_t));
    hid_t *mem_type_ids = (hid_t *)malloc(count * sizeof(hid_t));
    hid_t *mem_space_ids = (hid_t *)malloc(count * sizeof(hid_t));
    hid_t *file_space_ids = (hid_t *)malloc(count * sizeof(hid_t));
    void **bufs = (void **)malloc(count * sizeof(void *));

    if (!dset_ids || !mem_type_ids || !mem_space_ids || !file_space_ids || !bufs) {
        free(dset_ids);
        free(mem_type_ids);
        free(mem_space_ids);
        free(file_space_ids);
        free(bufs);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        dset_ids[i] = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, H5Screate(H5S_SCALAR), H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        mem_type_ids[i] = H5T_NATIVE_INT;
        mem_space_ids[i] = H5Screate(H5S_SCALAR);
        file_space_ids[i] = H5Screate(H5S_SCALAR);
        bufs[i] = malloc(sizeof(int));
        if (bufs[i]) {
            *((int *)bufs[i]) = (int)i;
        }
    }

    herr_t status = H5Dwrite_multi(count, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, H5P_DEFAULT, bufs);

    for (size_t i = 0; i < count; i++) {
        free(bufs[i]);
        H5Dclose(dset_ids[i]);
        H5Sclose(mem_space_ids[i]);
        H5Sclose(file_space_ids[i]);
    }

    free(dset_ids);
    free(mem_type_ids);
    free(mem_space_ids);
    free(file_space_ids);
    free(bufs);

    return status;
}

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return 0;

    create_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    size_t count = *((size_t *)Data);
    herr_t status = write_multi_datasets(file_id, count);

    if (status < 0) {
        fprintf(stderr, "Failed to write multiple datasets\n");
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

        LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    