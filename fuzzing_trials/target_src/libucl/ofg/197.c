#include <stdbool.h>
#include <stdint.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_197(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract a boolean value
    if (size < 1) {
        return 0;
    }

    // Extract a boolean value from the first byte of data
    bool bool_value = (data[0] % 2 == 0); // Even numbers as true, odd as false

    // Call the function-under-test
    ucl_object_t *obj = ucl_object_frombool(bool_value);

    // Clean up if necessary
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

    LLVMFuzzerTestOneInput_197(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
