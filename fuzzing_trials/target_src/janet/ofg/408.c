#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <janet.h>

// Remove 'extern "C"' as it is not needed in C code
int LLVMFuzzerTestOneInput_408(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create at least one Janet object
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Create a Janet object from the input data
    Janet janet_obj = janet_wrap_integer((int32_t)data[0]);

    // Initialize the integer pointers
    int32_t arg2 = 0;
    int32_t result = 0;

    // Call the function-under-test
    FILE *file = janet_getfile(&janet_obj, arg2, &result);

    // Perform cleanup
    if (file != NULL) {
        fclose(file);
    }

    // Deinitialize Janet
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

    LLVMFuzzerTestOneInput_408(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
