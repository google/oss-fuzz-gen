#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract an hid_t from the input data
    hid_t file_id = *((hid_t *)data);

    // Initialize a non-NULL pointer for the file number
    unsigned long file_number = 0;
    unsigned long *file_number_ptr = &file_number;

    // Call the function-under-test
    herr_t result = H5Fget_fileno(file_id, file_number_ptr);

    // Handle the result if necessary (e.g., logging, further processing)

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

    LLVMFuzzerTestOneInput_97(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
