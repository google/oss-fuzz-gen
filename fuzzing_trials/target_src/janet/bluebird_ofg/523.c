#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h> // Include this header to define size_t

// Assuming the function is declared in an external library
extern void janet_gcunlock(int);

// Fuzzing harness
int LLVMFuzzerTestOneInput_523(const uint8_t *data, size_t size) {
    // Ensure there is at least one byte to read
    if (size < 1) {
        return 0;
    }

    // Use the first byte of data to create a non-null integer
    int input = (int)data[0];

    // Call the function-under-test
    janet_gcunlock(input);

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

    LLVMFuzzerTestOneInput_523(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
