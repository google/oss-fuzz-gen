#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating a valid hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract a hid_t from the input data
    hid_t file_id = *(const hid_t *)data;

    // Allocate memory for the unsigned int to store the intent
    unsigned int intent = 0;

    // Call the function-under-test
    herr_t status = H5Fget_intent(file_id, &intent);

    // Use the status and intent for further logic if necessary
    // For fuzzing, we are primarily interested in calling the function

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

    LLVMFuzzerTestOneInput_158(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
