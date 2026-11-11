#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_249(const uint8_t *data, size_t size) {
    hid_t attribute_id;
    size_t buf_size;
    char *name_buf;
    ssize_t name_len;

    // Ensure there's enough data to extract meaningful values
    if (size < sizeof(hid_t) + sizeof(size_t)) {
        return 0;
    }

    // Extract hid_t and size_t from the input data
    memcpy(&attribute_id, data, sizeof(hid_t));
    memcpy(&buf_size, data + sizeof(hid_t), sizeof(size_t));

    // Allocate memory for the name buffer
    name_buf = (char *)malloc(buf_size + 1); // +1 for null-terminator
    if (name_buf == NULL) {
        return 0;
    }

    // Initialize the buffer with non-null values
    memset(name_buf, 'A', buf_size);
    name_buf[buf_size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    name_len = H5Aget_name(attribute_id, buf_size, name_buf);

    // Clean up
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

    LLVMFuzzerTestOneInput_249(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
