#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Ppublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("HDF5 dummy data", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    hid_t file_id, file_id2;
    herr_t status;
    bool minimize;
    
    write_dummy_file();

    // Step 1: Create a new HDF5 file
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Step 2: Get dataset no attributes hint
    status = H5Fget_dset_no_attrs_hint(file_id, &minimize);
    if (status < 0) goto cleanup;

    // Step 3: Set dataset no attributes hint
    status = H5Fset_dset_no_attrs_hint(file_id, true);
    if (status < 0) goto cleanup;

    // Step 4: Get dataset no attributes hint
    status = H5Fget_dset_no_attrs_hint(file_id, &minimize);
    if (status < 0) goto cleanup;

    // Step 5: Open the HDF5 file
    file_id2 = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id2 < 0) goto cleanup;

    // Step 6: Get dataset no attributes hint
    status = H5Fget_dset_no_attrs_hint(file_id2, &minimize);
    if (status < 0) goto cleanup2;

    // Step 7: Set dataset no attributes hint
    status = H5Fset_dset_no_attrs_hint(file_id2, false);
    if (status < 0) goto cleanup2;

    // Step 8: Get dataset no attributes hint
    status = H5Fget_dset_no_attrs_hint(file_id2, &minimize);
    if (status < 0) goto cleanup2;

    // Step 9: Get dataset no attributes hint
    status = H5Fget_dset_no_attrs_hint(file_id2, &minimize);
    if (status < 0) goto cleanup2;

    // Step 10: Set dataset no attributes hint
    status = H5Fset_dset_no_attrs_hint(file_id2, true);
    if (status < 0) goto cleanup2;

    // Step 11: Get dataset no attributes hint
    status = H5Fget_dset_no_attrs_hint(file_id2, &minimize);
    if (status < 0) goto cleanup2;

    // Step 12: Get dataset no attributes hint
    status = H5Fget_dset_no_attrs_hint(file_id2, &minimize);
    if (status < 0) goto cleanup2;

    // Step 13: Set dataset no attributes hint
    status = H5Fset_dset_no_attrs_hint(file_id2, false);
    if (status < 0) goto cleanup2;

    // Step 14: Get dataset no attributes hint
    status = H5Fget_dset_no_attrs_hint(file_id2, &minimize);
    if (status < 0) goto cleanup2;

    // Step 15: Get dataset no attributes hint
    status = H5Fget_dset_no_attrs_hint(file_id2, &minimize);
    if (status < 0) goto cleanup2;

cleanup2:
    // Step 16: Close the second file identifier
    H5Fclose(file_id2);

cleanup:
    // Step 17: Close the first file identifier
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
