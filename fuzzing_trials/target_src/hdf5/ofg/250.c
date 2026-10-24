#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_250(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < sizeof(hid_t) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract hid_t from the input data
    hid_t attr_id = *(const hid_t *)data;
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    // Extract size_t from the input data
    size_t buf_size = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Ensure the buffer size is within the remaining data size
    if (buf_size > size) {
        buf_size = size;
    }

    // Allocate a buffer for the name
    char *name_buf = (char *)malloc(buf_size + 1);
    if (name_buf == NULL) {
        return 0;
    }

    // Copy the remaining data into the buffer
    memcpy(name_buf, data, buf_size);
    name_buf[buf_size] = '\0';  // Null-terminate the buffer

    // Call the function-under-test
    ssize_t name_len = H5Aget_name(attr_id, buf_size, name_buf);

    // Free allocated memory
    free(name_buf);

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

    LLVMFuzzerTestOneInput_250(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
