#include <sys/stat.h>
#include "hdf5.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the inputs
    if (size < 4) return 0; // Adjusted to 4 since only 4 bytes are needed

    // Extract parts of the data for different parameters
    hid_t attr_id = (hid_t)data[0]; // Use a byte for the attribute ID
    hid_t dtype_id = (hid_t)data[1]; // Use a byte for the datatype ID
    unsigned int buf_size = (unsigned int)data[2]; // Use a byte for the buffer size
    hid_t es_id = (hid_t)data[3]; // Use a byte for the event set ID

    // Allocate memory for the buffer
    void *buf = malloc(buf_size);
    if (buf == NULL) return 0;

    // Call the function-under-test with the correct number of arguments
    herr_t result = H5Aread_async(attr_id, dtype_id, buf, es_id);

    // Free the allocated buffer
    free(buf);

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

    LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
