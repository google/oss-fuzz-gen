#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "/src/hdf5/src/H5Dpublic.h"
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Apublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) + sizeof(hsize_t) + sizeof(hid_t) + 1)
        return 0;

    write_dummy_file();

    // Extract parameters from data
    hid_t dset_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    hsize_t size[1];
    memcpy(size, Data, sizeof(hsize_t));
    Data += sizeof(hsize_t);
    Size -= sizeof(hsize_t);

    hid_t es_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    // Fuzz H5Dset_extent_async
    H5Dset_extent_async(dset_id, size, es_id);

    // Fuzz H5Aclose_async
    if (Size < sizeof(hid_t))
        return 0;

    hid_t attr_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);
    H5Aclose_async(attr_id, es_id);

    // Fuzz H5Dread_async
    if (Size < sizeof(hid_t) * 4 + sizeof(void *))
        return 0;

    hid_t mem_type_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    hid_t mem_space_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    hid_t file_space_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    hid_t dxpl_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    void *buf = (void *)Data;
    Data += sizeof(void *);

    H5Dread_async(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf, es_id);

    // Fuzz H5Fclose_async
    if (Size < sizeof(hid_t))
        return 0;

    hid_t file_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    H5Fclose_async(file_id, es_id);

    // Fuzz H5Fflush_async
    if (Size < sizeof(hid_t) + sizeof(H5F_scope_t))
        return 0;

    hid_t object_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    H5F_scope_t scope = *(H5F_scope_t *)Data;
    Data += sizeof(H5F_scope_t);

    H5Fflush_async(object_id, scope, es_id);

    // Fuzz H5Aexists_by_name_async
    if (Size < sizeof(hid_t) + 2)
        return 0;

    hid_t loc_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    const char *obj_name = (const char *)Data;
    Data += strlen(obj_name) + 1;
    const char *attr_name = (const char *)Data;
    Data += strlen(attr_name) + 1;
    bool exists;
    hid_t lapl_id = *(hid_t *)Data;
    Data += sizeof(hid_t);

    H5Aexists_by_name_async(loc_id, obj_name, attr_name, &exists, lapl_id, es_id);

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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
