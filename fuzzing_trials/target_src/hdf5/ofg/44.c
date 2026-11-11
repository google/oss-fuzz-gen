#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Define and initialize parameters for H5Dwrite_multi_async
    size_t count = 1;
    hid_t dset_id[1] = {H5I_INVALID_HID};
    hid_t mem_type_id[1] = {H5T_NATIVE_INT};
    hid_t mem_space_id[1] = {H5S_ALL};
    hid_t file_space_id[1] = {H5S_ALL};
    hid_t dxpl_id = H5P_DEFAULT;
    const void *buf[1] = {data};
    hid_t es_id = H5ES_NONE;

    // Call the function-under-test without the first three arguments
    herr_t status = H5Dwrite_multi_async(count, dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf, es_id);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_44(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
