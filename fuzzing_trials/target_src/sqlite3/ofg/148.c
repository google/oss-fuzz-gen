#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // Include for malloc and free
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    // Ensure that the size is at least 1 to avoid zero-length allocation
    if (size < 1) {
        return 0;
    }

    // Use the first byte of data to determine the integer parameter
    int n = (int)data[0];

    // Allocate memory for the randomness output
    void *output = malloc(size);
    if (output == NULL) {
        return 0;
    }

    // Call the function-under-test
    sqlite3_randomness(n, output);

    // Free the allocated memory
    free(output);

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

    LLVMFuzzerTestOneInput_148(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
