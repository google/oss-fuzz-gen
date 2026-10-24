// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Dcreate_anon at H5D.c:273:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Gpublic.h>
#include <H5Dpublic.h>
#include <H5Fpublic.h>
#include <H5Ppublic.h>
#include <H5Lpublic.h>
#include <H5Opublic.h>
#include <H5Spublic.h>
#include <H5Tpublic.h>

static void init_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

static hid_t create_hdf5_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static hid_t create_group(hid_t file_id, const char *group_name) {
    return H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
}

static hid_t create_dataset(hid_t file_id, const char *dataset_name) {
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t dataset_id = H5Dcreate2(file_id, dataset_name, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);
    return dataset_id;
}

int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    init_dummy_file();
    hid_t file_id = create_hdf5_file();
    if (file_id < 0) return 0;

    char group_name[256];
    snprintf(group_name, sizeof(group_name), "/group_%zu", Size);
    hid_t group_id = create_group(file_id, group_name);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // H5Gget_create_plist
    hid_t gcpl_id = H5Gget_create_plist(group_id);
    if (gcpl_id >= 0) {
        H5Pclose(gcpl_id);
    }

    // H5Gopen2
    hid_t open_group_id = H5Gopen2(file_id, group_name, H5P_DEFAULT);
    if (open_group_id >= 0) {
        H5Gclose(open_group_id);
    }

    // H5Glink2
    if (Size > 0) {
        char new_name[256];
        snprintf(new_name, sizeof(new_name), "/new_group_%zu", Size);
        H5Glink2(file_id, group_name, H5L_TYPE_HARD, file_id, new_name);
    }

    // H5Dcreate_anon
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t anon_dataset_id = H5Dcreate_anon(file_id, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT);
    if (anon_dataset_id >= 0) {
        H5Olink(anon_dataset_id, file_id, "/anon_dataset", H5P_DEFAULT, H5P_DEFAULT);
        H5Dclose(anon_dataset_id);
    }
    H5Sclose(space_id);

    // H5Dcreate2
    hid_t dataset_id = create_dataset(file_id, "/dataset");
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    H5Gclose(group_id);
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

        LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    