#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    ucl_object_t *obj;
    size_t reserve_size;

    // Ensure that the size is non-zero to avoid unnecessary calls with zero size.
    if (size == 0) {
        return 0;
    }

    // Initialize a UCL object
    obj = ucl_object_typed_new(UCL_OBJECT);

    // Use the first byte of data to determine the reserve size
    reserve_size = (size_t)data[0];

    // Call the function-under-test
    bool result = ucl_object_reserve(obj, reserve_size);

    // Clean up the UCL object
    ucl_object_unref(obj);

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

    LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
