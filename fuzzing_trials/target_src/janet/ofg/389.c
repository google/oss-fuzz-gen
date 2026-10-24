#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Since janet_wrap_pointer is a macro, we don't need to declare it as an extern function.

// Fuzzing function
int LLVMFuzzerTestOneInput_389(const uint8_t *data, size_t size) {
    if (size < sizeof(void *)) {
        return 0;
    }

    // Use the data as a pointer value by casting it
    void *ptr = (void *)(uintptr_t)(*(const uintptr_t *)data);

    // Call the function-under-test
    Janet result = janet_wrap_pointer(ptr);

    // Use the result in some way to avoid compiler optimizations removing the call
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

    LLVMFuzzerTestOneInput_389(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
