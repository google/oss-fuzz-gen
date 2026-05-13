#include <stdint.h>
#include <stddef.h>

// Assuming the janet_gcpressure function is declared in a header file
void janet_gcpressure(size_t);

int LLVMFuzzerTestOneInput_257(const uint8_t *data, size_t size) {
    // Ensure size is non-zero to call janet_gcpressure with a valid argument
    if (size > 0) {
        // Use the size of the input data as the argument for janet_gcpressure
        janet_gcpressure(size);
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

    LLVMFuzzerTestOneInput_257(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
