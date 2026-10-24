#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/hdf5/src/H5Dpublic.h"

int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) * 4 + sizeof(hsize_t)) return 0;

    hid_t dset_id = *(hid_t *)Data;
    hid_t mem_type_id = *(hid_t *)(Data + sizeof(hid_t));
    hid_t mem_space_id = *(hid_t *)(Data + 2 * sizeof(hid_t));
    hid_t file_space_id = *(hid_t *)(Data + 3 * sizeof(hid_t));
    hsize_t size = *(hsize_t *)(Data + 4 * sizeof(hid_t));
    hid_t dxpl_id = 0;
    hid_t es_id = 0;
    const void *buf = Data + 4 * sizeof(hid_t) + sizeof(hsize_t);

    H5Dwrite_async(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf, es_id);
    H5Dset_extent_async(dset_id, &size, es_id);
    H5Dclose_async(dset_id, es_id);
    H5Dread_async(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, (void *)buf, es_id);

    size_t count = 1;
    hid_t dset_ids[] = {dset_id};
    hid_t mem_type_ids[] = {mem_type_id};
    hid_t mem_space_ids[] = {mem_space_id};
    hid_t file_space_ids[] = {file_space_id};
    const void *bufs[] = {buf};
    void *buf_outs[] = {(void *)buf};

    H5Dwrite_multi_async(count, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, dxpl_id, bufs, es_id);
    H5Dread_multi_async(count, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, dxpl_id, buf_outs, es_id);

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

    LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
