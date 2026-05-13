#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Ensure data size is sufficient for testing
    if (size < sizeof(hid_t) + 1) {
        return 0;
    }

    // Extract an hid_t from the data
    hid_t file_id = *((hid_t *)data);
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    // Allocate a buffer for the name
    char name_buffer[256]; // Arbitrary buffer size for testing

    // Call the function-under-test
    ssize_t name_length = H5Fget_name(file_id, name_buffer, sizeof(name_buffer));

    // Check the result (you can add more checks if needed)
    if (name_length < 0) {
        // Handle error case if necessary
    } else {
        // Optionally, do something with the name (e.g., print it)
        // printf("File name: %s\n", name_buffer);
    }

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

    LLVMFuzzerTestOneInput_71(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
