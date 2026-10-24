#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a non-NULL pointer
    if (size < sizeof(void *)) {
        return 0;
    }

    // Create a non-NULL void pointer
    void *memory_location = (void *)(data);

    // Call the function-under-test
    struct ucl_emitter_functions *emitter_funcs = ucl_object_emit_memory_funcs(&memory_location);

    // Normally, one would use the emitter_funcs for further operations,
    // but since this is a fuzzing harness, we just ensure the function is called.
    // The function's behavior and return value are not checked here.

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
