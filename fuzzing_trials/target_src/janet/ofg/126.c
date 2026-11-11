#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Ensure that Janet is initialized before using any Janet functions
__attribute__((constructor))
static void initialize_janet_126() {
    janet_init();
}

// Fuzzing entry point
int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Ensure size is large enough to create a JanetFiber
    if (size < sizeof(JanetFiber)) {
        return 0;
    }

    // Allocate memory for a JanetFiber
    JanetFiber *fiber = (JanetFiber *)malloc(sizeof(JanetFiber));
    if (!fiber) {
        return 0;
    }

    // Initialize the fiber with some data
    // Note: This is a simplified initialization. In a real scenario,
    // you would properly initialize the fiber according to the Janet API.
    fiber->capacity = 10;
    fiber->frame = 0;
    fiber->stackstart = 0;
    fiber->stacktop = 0;
    fiber->flags = 0;

    // Call the function-under-test
    JanetFiberStatus status = janet_fiber_status(fiber);

    // Clean up
    free(fiber);

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

    LLVMFuzzerTestOneInput_126(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
