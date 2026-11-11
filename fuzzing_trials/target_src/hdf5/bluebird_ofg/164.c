#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    if (size < sizeof(hid_t) + sizeof(haddr_t)) {
        return 0;
    }

    // Extract hid_t from the input data
    hid_t file_id = *(const hid_t *)data;
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    // Allocate memory for haddr_t
    haddr_t eoa;
    
    // Call the function-under-test
    herr_t result = H5Fget_eoa(file_id, &eoa);

    // Use the result and eoa in some way to avoid compiler optimizations
    (void)result;
    (void)eoa;

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

    LLVMFuzzerTestOneInput_164(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
