#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Apublic.h"
#include "/src/hdf5/src/H5Spublic.h"
#include "/src/hdf5/src/H5Tpublic.h"
#include "/src/hdf5/src/H5Ppublic.h"

static hid_t create_hdf5_file() {
    return H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
}

static hid_t create_attribute(hid_t file_id) {
    hid_t space_id = H5Screate(H5S_SCALAR);
    if (space_id < 0) return -1;

    hid_t attr_id = H5Acreate2(file_id, "attr1", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT);
    H5Sclose(space_id);
    return attr_id;
}

int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_hdf5_file();
    if (file_id < 0) return 0;

    hid_t attr_id = create_attribute(file_id);
    if (attr_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    char old_name[10] = "attr1";
    char new_name[10];
    snprintf(new_name, sizeof(new_name), "attr%u", Data[0] % 10);

    for (int i = 0; i < 4; i++) {
        H5Arename(file_id, old_name, new_name);
        snprintf(old_name, sizeof(old_name), "attr%u", Data[0] % 10);
        snprintf(new_name, sizeof(new_name), "attr%u", (Data[0] + i + 1) % 10);
    }

    for (int i = 0; i < 4; i++) {
        H5Arename_by_name(file_id, ".", old_name, new_name, H5P_DEFAULT);
        snprintf(old_name, sizeof(old_name), "attr%u", (Data[0] + i + 1) % 10);
        snprintf(new_name, sizeof(new_name), "attr%u", (Data[0] + i + 2) % 10);
    }

    H5Aclose(attr_id);
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
