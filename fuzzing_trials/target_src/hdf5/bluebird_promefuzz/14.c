#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/hdf5/src/H5Dpublic.h"
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Spublic.h"
#include "/src/hdf5/src/H5Tpublic.h"
#include "/src/hdf5/src/H5Ppublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy data", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    write_dummy_file();

    hid_t file_id, dataset_id, space_id, type_id;
    herr_t status;

    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    hsize_t dims[1] = {Size};
    space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    type_id = H5Tcopy(H5T_NATIVE_UINT8);
    if (type_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    dataset_id = H5Dcreate2(file_id, "dataset", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) {
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }


    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from H5Dcreate2 to H5Acreate_by_name using the plateau pool
    const char *obj_name = "dummy_object";
    const char *attr_name = "dummy_attribute";
    hid_t ret_H5Acreate_by_name_fezoi = H5Acreate_by_name(file_id, obj_name, attr_name, file_id, dataset_id, file_id, dataset_id, dataset_id);
    // End mutation: Producer.SPLICE_MUTATOR
    
    status = H5Dwrite(dataset_id, type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, Data);
    if (status < 0) {
        H5Dclose(dataset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of H5Fflush
    status = H5Fflush(file_id, H5F_SCOPE_GLOBAL);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (status < 0) {
        H5Dclose(dataset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    ssize_t image_size = H5Fget_file_image(file_id, NULL, 0);
    if (image_size > 0) {
        void *image_buf = malloc(image_size);
        if (image_buf) {
            H5Fget_file_image(file_id, image_buf, image_size);
            free(image_buf);
        }
    }

    H5Dclose(dataset_id);
    H5Tclose(type_id);
    H5Sclose(space_id);
    H5Fclose(file_id);

    file_id = H5Fopen("./dummy_file", H5F_ACC_RDONLY, H5P_DEFAULT);
    if (file_id >= 0) {
        H5Fclose(file_id);
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from H5Fopen to H5Awrite
    hid_t ret_H5Dget_create_plist_pdmnk = H5Dget_create_plist(0);
    herr_t ret_H5Awrite_jalbb = H5Awrite(ret_H5Dget_create_plist_pdmnk, file_id, (const void *)"r");
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
