#include <stdint.h>
#include <stdbool.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_198(const uint8_t *data, size_t size) {
    // Ensure there is at least one byte to read for the boolean value
    if (size < 1) {
        return 0;
    }

    // Use the first byte of the input data to determine the boolean value
    bool bool_value = (data[0] % 2) == 0; // Even values are true, odd values are false

    // Call the function-under-test
    ucl_object_t *obj = ucl_object_frombool(bool_value);

    // Clean up the created UCL object
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

    LLVMFuzzerTestOneInput_198(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
