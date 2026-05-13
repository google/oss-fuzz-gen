#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy
#include <janet.h>

int LLVMFuzzerTestOneInput_359(const uint8_t *data, size_t size) {
    if (size < sizeof(JanetFiber) + sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Allocate memory for JanetFiber and Janet
    JanetFiber *fiber = (JanetFiber *)malloc(sizeof(JanetFiber));
    if (!fiber) {
        janet_deinit();
        return 0;
    }

    Janet janet_value;

    // Copy data into the JanetFiber and Janet
    memcpy(fiber, data, sizeof(JanetFiber));
    memcpy(&janet_value, data + sizeof(JanetFiber), sizeof(Janet));

    // Call the function-under-test
    janet_schedule(fiber, janet_value);

    // Clean up
    free(fiber);
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

    LLVMFuzzerTestOneInput_359(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
