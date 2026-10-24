#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_355(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Create two Janet objects from the input data
    Janet arg1 = janet_wrap_integer((int32_t)data[0]);
    Janet arg2 = janet_wrap_integer((int32_t)data[1]);

    // Call the function-under-test
    Janet result = janet_in(arg1, arg2);

    // Clean up Janet VM
    janet_deinit();

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

    LLVMFuzzerTestOneInput_355(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
