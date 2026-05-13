#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    if (size < sizeof(hid_t) * 2 + sizeof(hsize_t) + sizeof(uint32_t) + sizeof(size_t)) {
        return 0; // Not enough data to fill all parameters
    }

    // Initialize parameters
    hid_t dset_id = *(const hid_t *)data;
    hid_t mem_type_id = *(const hid_t *)(data + sizeof(hid_t));

    const hsize_t *offset = (const hsize_t *)(data + sizeof(hid_t) * 2);

    uint32_t *filters = (uint32_t *)(data + sizeof(hid_t) * 2 + sizeof(hsize_t));

    void *buf = (void *)(data + sizeof(hid_t) * 2 + sizeof(hsize_t) + sizeof(uint32_t));

    size_t *buf_size = (size_t *)(data + sizeof(hid_t) * 2 + sizeof(hsize_t) + sizeof(uint32_t) + sizeof(void *));

    // Call the function-under-test
    herr_t result = H5Dread_chunk2(dset_id, mem_type_id, offset, filters, buf, buf_size);

    // Use the result to avoid compiler optimizations that remove the function call
    (void)result;

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

    LLVMFuzzerTestOneInput_11(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
