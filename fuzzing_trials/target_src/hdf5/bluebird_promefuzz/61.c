#include <sys/stat.h>
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
#include "/src/hdf5/src/H5Dpublic.h"
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Spublic.h"
#include "/src/hdf5/src/H5Tpublic.h"
#include "/src/hdf5/src/H5Ppublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "Dummy HDF5 data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_61(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    hid_t file_id, dataset_id, space_id, type_id, lcpl_id, dcpl_id, dapl_id;
    ssize_t obj_count;
    hid_t obj_id_list[10];

    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    space_id = H5Screate(H5S_SIMPLE);
    type_id = H5Tcopy(H5T_NATIVE_INT);
    lcpl_id = H5P_DEFAULT;
    dcpl_id = H5P_DEFAULT;
    dapl_id = H5P_DEFAULT;

    dataset_id = H5Dcreate2(file_id, "dataset", type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dataset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    obj_count = H5Fget_obj_count(file_id, H5F_OBJ_ALL);
    if (obj_count >= 0) {
        H5Fget_obj_ids(file_id, H5F_OBJ_ALL, 10, obj_id_list);
    }

    H5Dclose(dataset_id);
    H5Fclose(file_id);

    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    dataset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    H5Fclose(file_id);

    obj_count = H5Fget_obj_count(H5F_OBJ_ALL, H5F_OBJ_ALL);
    if (obj_count >= 0) {
        H5Fget_obj_ids(H5F_OBJ_ALL, H5F_OBJ_ALL, 10, obj_id_list);
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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
