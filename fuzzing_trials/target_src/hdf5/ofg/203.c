#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

// Dummy gather function
herr_t dummy_gather_func(void *buf, size_t nbytes, void *op_data) {
    // Do nothing
    return 0;
}

int LLVMFuzzerTestOneInput_203(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create necessary buffers
    if (size < sizeof(hid_t) * 2 + sizeof(size_t)) {
        return 0;
    }

    // Initialize variables
    hid_t src_space_id = *((hid_t *)data);
    hid_t type_id = *((hid_t *)(data + sizeof(hid_t)));
    size_t dst_buf_size = *((size_t *)(data + 2 * sizeof(hid_t)));

    // Ensure dst_buf_size is not zero to avoid null pointer issues
    if (dst_buf_size == 0) {
        dst_buf_size = 1;
    }

    // Allocate memory for source and destination buffers
    const void *src_buf = data + 2 * sizeof(hid_t) + sizeof(size_t);
    void *dst_buf = malloc(dst_buf_size);

    // Call the function-under-test
    H5Dgather(src_space_id, src_buf, type_id, dst_buf_size, dst_buf, dummy_gather_func, NULL);

    // Free allocated memory
    free(dst_buf);

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

    LLVMFuzzerTestOneInput_203(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
