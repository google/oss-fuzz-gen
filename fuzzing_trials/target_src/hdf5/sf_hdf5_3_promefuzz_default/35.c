// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gopen1 at H5Gdeprec.c:247:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gcreate1 at H5Gdeprec.c:153:1 in H5Gpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Dopen1 at H5Ddeprec.c:166:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>
#include <H5Ppublic.h>
#include <H5Fpublic.h>
#include <string.h>

#define DUMMY_FILE "./dummy_file"

static hid_t create_dummy_hdf5_file() {
    hid_t file_id = H5Fcreate(DUMMY_FILE, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void close_hdf5_objects(hid_t *objects, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (objects[i] >= 0) {
            H5Gclose(objects[i]);
        }
    }
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    hid_t file_id = create_dummy_hdf5_file();
    if (file_id < 0) return 0;

    char group_name[256];
    size_t name_len = (Size < 255) ? Size : 255;
    memcpy(group_name, Data, name_len);
    group_name[name_len] = '\0';

    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t objects[6];
    objects[0] = H5Gopen1(file_id, group_name);
    objects[1] = H5Gopen2(file_id, group_name, H5P_DEFAULT);
    objects[2] = H5Gcreate1(file_id, group_name, 0);
    objects[3] = H5Gget_create_plist(group_id);

    // Assuming Data + 1 is a valid dataset name for H5Dopen1
    char dataset_name[256];
    size_t dataset_name_len = (Size - 1 < 255) ? Size - 1 : 255;
    memcpy(dataset_name, Data + 1, dataset_name_len);
    dataset_name[dataset_name_len] = '\0';

    objects[4] = H5Dopen1(file_id, dataset_name);

    close_hdf5_objects(objects, 5);
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

        LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    