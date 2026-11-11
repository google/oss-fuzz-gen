#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_370(const uint8_t *data, size_t size) {
    // Ensure there's enough data to initialize the parameters
    if (size < sizeof(JanetFunction) + sizeof(int32_t) * 2 + sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Initialize parameters
    JanetFunction *func = (JanetFunction *)data;
    int32_t capacity = *((int32_t *)(data + sizeof(JanetFunction)));
    int32_t flags = *((int32_t *)(data + sizeof(JanetFunction) + sizeof(int32_t)));
    const Janet *argv = (const Janet *)(data + sizeof(JanetFunction) + sizeof(int32_t) * 2);

    // Call the function-under-test
    JanetFiber *fiber = janet_fiber(func, capacity, flags, argv);

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

    LLVMFuzzerTestOneInput_370(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
