#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/hdf5/src/H5Dpublic.h"
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Apublic.h"
#include "/src/hdf5/src/H5Ppublic.h"
#include "/src/hdf5/src/H5Spublic.h"
#include "/src/hdf5/src/H5Tpublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "This is a dummy HDF5 file.\n");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    hid_t file_id = -1, dataset_id = -1, attr_id = -1;
    herr_t status;
    hid_t fapl_id = H5P_DEFAULT, fcpl_id = H5P_DEFAULT, dcpl_id = H5P_DEFAULT, acpl_id = H5P_DEFAULT;
    hid_t type_id = H5T_NATIVE_INT, space_id = H5Screate(H5S_SCALAR);

    // H5Fcreate
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, fcpl_id, fapl_id);
    if (file_id < 0) goto cleanup;

    // H5Fclose
    status = H5Fclose(file_id);
    if (status < 0) goto cleanup;

    // H5Dcreate1
    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, fapl_id);
    if (file_id < 0) goto cleanup;
    dataset_id = H5Dcreate1(file_id, "dataset", type_id, space_id, dcpl_id);
    if (dataset_id < 0) goto cleanup;

    // H5Fopen
    status = H5Fclose(file_id);
    if (status < 0) goto cleanup;
    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, fapl_id);
    if (file_id < 0) goto cleanup;

    // H5Dopen1
    hid_t dset_id = H5Dopen1(file_id, "dataset");
    if (dset_id < 0) goto cleanup;

    // H5Acreate1
    attr_id = H5Acreate1(dset_id, "attribute", type_id, space_id, acpl_id);
    if (attr_id < 0) goto cleanup;

    // Additional H5Fopen calls
    status = H5Fclose(file_id);
    if (status < 0) goto cleanup;
    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, fapl_id);
    if (file_id < 0) goto cleanup;

    dset_id = H5Dopen1(file_id, "dataset");
    if (dset_id < 0) goto cleanup;

    attr_id = H5Acreate1(dset_id, "attribute", type_id, space_id, acpl_id);
    if (attr_id < 0) goto cleanup;

    status = H5Fclose(file_id);
    if (status < 0) goto cleanup;
    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, fapl_id);
    if (file_id < 0) goto cleanup;

    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, fapl_id);
    if (file_id < 0) goto cleanup;

    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, fapl_id);
    if (file_id < 0) goto cleanup;

cleanup:
    if (file_id >= 0) H5Fclose(file_id);
    if (dataset_id >= 0) H5Dclose(dataset_id);
    if (attr_id >= 0) H5Aclose(attr_id);
    if (space_id >= 0) H5Sclose(space_id);

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
