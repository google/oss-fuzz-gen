// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aopen at H5A.c:531:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Awrite at H5A.c:908:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aread at H5A.c:1014:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
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

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "Dummy data for HDF5 file.");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    write_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t group_id = H5Gcreate2(file_id, "group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t attr_id = H5Acreate2(group_id, "attr", H5T_NATIVE_INT, H5Screate(H5S_SCALAR), H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id < 0) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    hid_t group_id_open = H5Gopen2(file_id, "group", H5P_DEFAULT);
    if (group_id_open < 0) {
        H5Aclose(attr_id);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    hid_t attr_id_open = H5Aopen(group_id_open, "attr", H5P_DEFAULT);
    if (attr_id_open < 0) {
        H5Aclose(attr_id);
        H5Gclose(group_id_open);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    int data = 42;
    if (H5Awrite(attr_id_open, H5T_NATIVE_INT, &data) < 0) {
        H5Aclose(attr_id_open);
        H5Aclose(attr_id);
        H5Gclose(group_id_open);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    int read_data;
    if (H5Aread(attr_id_open, H5T_NATIVE_INT, &read_data) < 0) {
        H5Aclose(attr_id_open);
        H5Aclose(attr_id);
        H5Gclose(group_id_open);
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }

    H5Aclose(attr_id_open);
    H5Aclose(attr_id);
    H5Gclose(group_id_open);
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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    