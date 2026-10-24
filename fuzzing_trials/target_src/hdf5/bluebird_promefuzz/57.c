#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/hdf5/src/H5Dpublic.h"
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Apublic.h"

static hid_t create_dummy_file() {
    return H5Fcreate_async("./dummy_file", 0, -1, -1, -1);
}

static hid_t create_dummy_dataset(hid_t file_id) {
    return H5Dcreate_async(file_id, "dummy_dataset", -1, -1, -1, -1, -1, -1);
}

static void fuzz_H5Dget_space_async(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    hid_t dset_id = create_dummy_dataset(file_id);
    hid_t es_id = -1;

    if (Size > 0) {
        es_id = (hid_t)Data[0];
    }

    H5Dget_space_async(dset_id, es_id);
    H5Fclose(file_id);
}

static void fuzz_H5Dread_async(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    hid_t dset_id = create_dummy_dataset(file_id);
    hid_t es_id = -1;
    void *buf = NULL;

    if (Size > 0) {
        es_id = (hid_t)Data[0];
    }

    H5Dread_async(dset_id, -1, -1, -1, -1, buf, es_id);
    H5Fclose(file_id);
}

static void fuzz_H5Dopen_async(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    hid_t es_id = -1;

    if (Size > 0) {
        es_id = (hid_t)Data[0];
    }

    H5Dopen_async(file_id, "dummy_dataset", -1, es_id);
    H5Fclose(file_id);
}

static void fuzz_H5Acreate_async(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    hid_t es_id = -1;

    if (Size > 0) {
        es_id = (hid_t)Data[0];
    }

    H5Acreate_async(file_id, "dummy_attr", -1, -1, -1, -1, es_id);
    H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    fuzz_H5Dget_space_async(Data, Size);
    fuzz_H5Dread_async(Data, Size);
    fuzz_H5Dopen_async(Data, Size);
    fuzz_H5Acreate_async(Data, Size);
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
