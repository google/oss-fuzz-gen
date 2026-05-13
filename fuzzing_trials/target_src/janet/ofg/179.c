#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern int janet_indexed_view(Janet, const Janet **, int32_t *);

int LLVMFuzzerTestOneInput_179(const uint8_t *data, size_t size) {
    // Ensure we have enough data for a Janet object and an integer
    if (size < sizeof(Janet) + sizeof(int32_t)) {
        return 0;
    }

    // Initialize Janet environment
    janet_init();

    // Create a Janet object from the input data
    Janet janet_obj = janet_wrap_number((double)data[0]);

    // Create a pointer for the view
    const Janet *view = NULL;

    // Create an integer for the length
    int32_t length = 0;

    // Call the function-under-test
    int result = janet_indexed_view(janet_obj, &view, &length);

    // Cleanup Janet environment
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

    LLVMFuzzerTestOneInput_179(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
