// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fset_libver_bounds at H5F.c:2404:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gget_num_objs at H5Gdeprec.c:885:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
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
#include <hdf5.h>

#define DUMMY_FILE "./dummy_file"
#define DUMMY_GROUP_NAME "dummy_group"
#define DUMMY_DATASET_NAME "dummy_dataset"

static void create_dummy_file() {
    hid_t file_id = H5Fcreate(DUMMY_FILE, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file.\n");
        return;
    }
    H5Fclose(file_id);
}

static hid_t open_dummy_file() {
    return H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
}

int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    create_dummy_file();
    hid_t file_id = open_dummy_file();
    if (file_id < 0) return 0;

    // Fuzz H5Fset_libver_bounds
    if (Size >= 2) {
        H5F_libver_t low = Data[0] % H5F_LIBVER_NBOUNDS;
        H5F_libver_t high = Data[1] % H5F_LIBVER_NBOUNDS;
        H5Fset_libver_bounds(file_id, low, high);
    }

    // Fuzz H5Gcreate2
    hid_t group_id = H5Gcreate2(file_id, DUMMY_GROUP_NAME, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        // Fuzz H5Gget_num_objs
        hsize_t num_objs;
        H5Gget_num_objs(group_id, &num_objs);

        // Fuzz H5Gget_info
        H5G_info_t ginfo;
        H5Gget_info(group_id, &ginfo);

        // Fuzz H5Glink2
        if (Size >= 3) {
            H5G_link_t type = Data[2] % 2 ? H5L_TYPE_HARD : H5L_TYPE_SOFT;
            H5Glink2(group_id, DUMMY_GROUP_NAME, type, group_id, "linked_group");
        }

        H5Gclose(group_id);
    }

    // Fuzz H5Dwrite
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t dset_id = H5Dcreate2(file_id, DUMMY_DATASET_NAME, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id >= 0) {
        int dummy_data = 42;
        H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, &dummy_data);
        H5Dclose(dset_id);
    }
    H5Sclose(space_id);

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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    