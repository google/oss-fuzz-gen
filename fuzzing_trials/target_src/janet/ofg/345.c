#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_345(const uint8_t *data, size_t size) {
    // Since janet_vm_alloc does not take any parameters, we can call it directly.
    JanetVM *vm = janet_vm_alloc();

    // Normally, you would perform operations on the JanetVM instance here.
    // However, since this is a simple allocation function, there's not much to do.

    // Return 0 to indicate that the fuzzer should continue testing.
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

    LLVMFuzzerTestOneInput_345(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
