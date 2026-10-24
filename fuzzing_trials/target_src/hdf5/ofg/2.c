#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    if (size < sizeof(hid_t) * 4 + sizeof(size_t)) {
        return 0;
    }

    size_t num_datasets = 1; // We will test with a single dataset
    hid_t file_space_id = *((hid_t *)data);
    hid_t mem_space_id = *((hid_t *)(data + sizeof(hid_t)));
    hid_t plist_id = *((hid_t *)(data + 2 * sizeof(hid_t)));
    hid_t file_id = *((hid_t *)(data + 3 * sizeof(hid_t)));
    hid_t dxpl_id = *((hid_t *)(data + 4 * sizeof(hid_t)));

    const void *buf = data + 5 * sizeof(hid_t);

    // Create arrays for the function call
    hid_t *dset_ids = (hid_t *)malloc(num_datasets * sizeof(hid_t));
    hid_t *mem_space_ids = (hid_t *)malloc(num_datasets * sizeof(hid_t));
    hid_t *file_space_ids = (hid_t *)malloc(num_datasets * sizeof(hid_t));
    hid_t *plist_ids = (hid_t *)malloc(num_datasets * sizeof(hid_t));
    const void **bufs = (const void **)malloc(num_datasets * sizeof(void *));

    if (!dset_ids || !mem_space_ids || !file_space_ids || !plist_ids || !bufs) {
        free(dset_ids);
        free(mem_space_ids);
        free(file_space_ids);
        free(plist_ids);
        free(bufs);
        return 0;
    }

    // Initialize the arrays
    for (size_t i = 0; i < num_datasets; i++) {
        dset_ids[i] = file_id;
        mem_space_ids[i] = mem_space_id;
        file_space_ids[i] = file_space_id;
        plist_ids[i] = plist_id;
        bufs[i] = buf;
    }

    // Call the function-under-test
    H5Dwrite_multi(num_datasets, dset_ids, mem_space_ids, file_space_ids, plist_ids, dxpl_id, bufs);

    free(dset_ids);
    free(mem_space_ids);
    free(file_space_ids);
    free(plist_ids);
    free(bufs);

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

    LLVMFuzzerTestOneInput_2(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
