#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
size_t janet_os_rwlock_size();

int LLVMFuzzerTestOneInput_343(const uint8_t *data, size_t size) {
    // Call the function-under-test
    size_t rwlock_size = janet_os_rwlock_size();

    // Use the result in some way to avoid compiler optimizations removing the call
    if (rwlock_size > 0) {
        // Perform some operations with the input data
        // This is just to ensure the function call is not optimized away
        size_t sum = 0;
        for (size_t i = 0; i < size; i++) {
            sum += data[i];
        }

        // Use the sum in a way that depends on the function-under-test
        if (sum % rwlock_size == 0) {
            // This is a trivial operation to ensure the function call's result affects the logic
            (void)sum;
        }
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

    LLVMFuzzerTestOneInput_343(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
