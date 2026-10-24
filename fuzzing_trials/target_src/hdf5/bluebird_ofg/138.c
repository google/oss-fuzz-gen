#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

herr_t my_operator_138(void *elem, hid_t type_id, unsigned ndim, const hsize_t *point, void *operator_data) {
    // Example operator function, does nothing
    return 0;
}

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    if (size < sizeof(hid_t) * 2) {
        return 0;
    }

    // Initialize the parameters for H5Diterate
    void *buf = (void *)data;
    hid_t type_id = *((hid_t *)data);
    hid_t space_id = *(((hid_t *)data) + 1);
    H5D_operator_t op = my_operator_138;
    void *operator_data = NULL;

    // Call the function-under-test
    H5Diterate(buf, type_id, space_id, op, operator_data);

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

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
