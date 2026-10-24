#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Ensure the size is at least the size of a double
    if (size < sizeof(double)) {
        return 0;
    }

    // Initialize a double from the input data
    double value;
    memcpy(&value, data, sizeof(double));

    // Call the function-under-test
    ucl_object_t *obj = ucl_object_fromdouble(value);

    // Clean up the created object
    if (obj != NULL) {
        ucl_object_unref(obj);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
