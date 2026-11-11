#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_162(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating a Janet object
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet object from the input data
    const Janet *janet_obj = (const Janet *)data;

    // Use a fixed index for fuzzing purposes
    int32_t index = 0;

    // Call the function-under-test
    JanetTable *result = janet_gettable(janet_obj, index);

    // The result is not used further, as we're just testing for crashes
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_162(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
