#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_252(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for at least one element of each type
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize input and output buffers
    const void *src_buf = (const void *)data;
    void *dst_buf = malloc(size);
    if (dst_buf == NULL) {
        return 0;
    }

    // Initialize data types
    hid_t src_type = H5T_NATIVE_INT;
    hid_t dst_type = H5T_NATIVE_INT;
    hid_t plist_id = H5P_DEFAULT;

    // Call the function-under-test
    herr_t result = H5Dfill(src_buf, src_type, dst_buf, dst_type, plist_id);

    // Clean up
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

    LLVMFuzzerTestOneInput_252(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
