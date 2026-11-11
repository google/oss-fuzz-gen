#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hdf5.h"
#include "/src/hdf5/src/H5Dpublic.h"

static hid_t create_dummy_dataset() {
    hid_t file_id, space_id, dset_id;
    hsize_t dims[2] = {10, 10};
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    space_id = H5Screate_simple(2, dims, NULL);
    dset_id = H5Dcreate2(file_id, "dset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);
    H5Fclose(file_id);
    return dset_id;
}

static void cleanup_dataset(hid_t dset_id) {
    H5Dclose(dset_id);
    remove("./dummy_file");
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hsize_t) * 2) return 0;

    hid_t dset_id = create_dummy_dataset();

    // Test H5Dget_space_status
    H5D_space_status_t allocation;
    H5Dget_space_status(dset_id, &allocation);

    // Test H5Dset_extent
    hsize_t new_size[2];
    memcpy(new_size, Data, sizeof(hsize_t) * 2);
    H5Dset_extent(dset_id, new_size);

    // Test H5Dget_create_plist
    hid_t plist_id = H5Dget_create_plist(dset_id);
    if (plist_id >= 0) {
        H5Pclose(plist_id);
    }

    // Test H5Ddebug
    H5Ddebug(dset_id);

    // Test H5Dget_storage_size
    H5Dget_storage_size(dset_id);

    // Test H5Drefresh
    H5Drefresh(dset_id);

    cleanup_dataset(dset_id);

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
