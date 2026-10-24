#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared in a header file included in the project
void janet_gcpressure(size_t pressure);

int LLVMFuzzerTestOneInput_258(const uint8_t *data, size_t size) {
    // Convert the input data to a size_t value
    size_t pressure = 0;

    // Ensure that the size is at least the size of size_t
    if (size >= sizeof(size_t)) {
        // Copy the bytes from data to pressure
        for (size_t i = 0; i < sizeof(size_t); i++) {
            pressure |= ((size_t)data[i]) << (8 * i);
        }
    } else {
        // If the size is less than size_t, use the available bytes
        for (size_t i = 0; i < size; i++) {
            pressure |= ((size_t)data[i]) << (8 * i);
        }
    }

    // Call the function-under-test
    janet_gcpressure(pressure);

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

    LLVMFuzzerTestOneInput_258(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
