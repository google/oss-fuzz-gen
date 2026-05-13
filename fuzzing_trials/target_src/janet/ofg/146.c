#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Ensure Janet VM is initialized before using any Janet functions
static void initialize_janet_vm() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

extern int32_t janet_optnat(const Janet *argv, int32_t n, int32_t def, int32_t max);

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    // Ensure Janet VM is initialized
    initialize_janet_vm();

    // Ensure there is enough data to extract the necessary parameters
    if (size < sizeof(int32_t) * 4) {
        return 0;
    }

    // Initialize the parameters
    Janet argv[1];
    argv[0] = janet_wrap_integer(*(int32_t *)data); // Assuming the first part of data is an integer

    int32_t n = *(int32_t *)(data + sizeof(int32_t));
    int32_t def = *(int32_t *)(data + 2 * sizeof(int32_t));
    int32_t max = *(int32_t *)(data + 3 * sizeof(int32_t));

    // Ensure n is within the bounds of the argv array
    if (n < 0 || n >= 1) {
        return 0;
    }

    // Call the function-under-test
    int32_t result = janet_optnat(argv, n, def, max);

    // Use the result to avoid any compiler optimizations that might remove the call
    volatile int32_t prevent_optimization = result;
    (void)prevent_optimization;

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

    LLVMFuzzerTestOneInput_146(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
