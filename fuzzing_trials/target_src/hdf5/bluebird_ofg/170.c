#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Interpret the first bytes of data as a hid_t
    hid_t file_id = *(const hid_t *)data;

    // Call the function-under-test
    herr_t result = H5Fclear_elink_file_cache(file_id);

    // Use the result to prevent optimization out
    (void)result;

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

    LLVMFuzzerTestOneInput_170(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
