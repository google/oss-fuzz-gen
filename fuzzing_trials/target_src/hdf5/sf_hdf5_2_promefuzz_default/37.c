// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fget_obj_ids at H5F.c:333:1 in H5Fpublic.h
// H5Fget_freespace at H5F.c:1617:1 in H5Fpublic.h
// H5Fget_intent at H5F.c:1540:1 in H5Fpublic.h
// H5Fget_create_plist at H5F.c:106:1 in H5Fpublic.h
// H5Freopen at H5F.c:1440:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Dpublic.h"
#include "H5Tpublic.h"
#include "H5Spublic.h"
#include "H5Ppublic.h"

#define DUMMY_FILE "./dummy_file"

static void create_dummy_file() {
    FILE *file = fopen(DUMMY_FILE, "w");
    if (file) {
        fprintf(file, "HDF5 dummy content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) + sizeof(unsigned) + sizeof(size_t)) {
        return 0;
    }

    create_dummy_file();

    hid_t file_id = *((hid_t *)Data);
    unsigned types = *((unsigned *)(Data + sizeof(hid_t)));
    size_t max_objs = *((size_t *)(Data + sizeof(hid_t) + sizeof(unsigned)));
    hid_t obj_id_list[10];

    ssize_t num_objs = H5Fget_obj_ids(file_id, types, max_objs, obj_id_list);
    if (num_objs < 0) {
        fprintf(stderr, "H5Fget_obj_ids failed\n");
    }

    hssize_t free_space = H5Fget_freespace(file_id);
    if (free_space < 0) {
        fprintf(stderr, "H5Fget_freespace failed\n");
    }

    unsigned intent;
    herr_t intent_status = H5Fget_intent(file_id, &intent);
    if (intent_status < 0) {
        fprintf(stderr, "H5Fget_intent failed\n");
    }

    hid_t plist_id = H5Fget_create_plist(file_id);
    if (plist_id < 0) {
        fprintf(stderr, "H5Fget_create_plist failed\n");
    } else {
        H5Pclose(plist_id);
    }

    hid_t new_file_id = H5Freopen(file_id);
    if (new_file_id < 0) {
        fprintf(stderr, "H5Freopen failed\n");
    } else {
        H5Fclose(new_file_id);
    }

    hid_t dataset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, H5S_SCALAR, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) {
        fprintf(stderr, "H5Dcreate2 failed\n");
    } else {
        H5Dclose(dataset_id);
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

        LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    