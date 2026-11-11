#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
size_t janet_os_rwlock_size();

// Fuzzing harness for janet_os_rwlock_size
int LLVMFuzzerTestOneInput_342(const uint8_t *data, size_t size) {
    // Call the function-under-test
    size_t rwlock_size = janet_os_rwlock_size();

    // Use the result in some way to avoid compiler optimizations
    // Here, we simply print it, but in a real fuzzing environment, 
    // you might want to check the value or use it in further logic.
    (void)rwlock_size;

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

    LLVMFuzzerTestOneInput_342(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
