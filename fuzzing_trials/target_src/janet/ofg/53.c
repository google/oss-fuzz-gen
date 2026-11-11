#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Ensure that the Janet library is initialized before calling janet_root_fiber
__attribute__((constructor))
static void init_janet_library() {
    janet_init();
}

int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Call the function-under-test
    JanetFiber *root_fiber = janet_root_fiber();

    // Use the root_fiber in some way to ensure it is not optimized away
    // Here, we simply check if it's not NULL and perform a dummy operation
    if (root_fiber != NULL) {
        // Dummy operation: Get the status of the fiber
        JanetFiberStatus status = janet_fiber_status(root_fiber);
        (void)status; // Suppress unused variable warning
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_53(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
