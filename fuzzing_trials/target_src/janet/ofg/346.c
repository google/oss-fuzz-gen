#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function signature for the function-under-test
void janet_free(void *ptr);

int LLVMFuzzerTestOneInput_346(const uint8_t *data, size_t size) {
    // Allocate memory based on the input size
    void *ptr = malloc(size);
    if (ptr == NULL) {
        // If allocation fails, return immediately
        return 0;
    }

    // Copy the input data into the allocated memory
    memcpy(ptr, data, size);

    // Call the function-under-test
    janet_free(ptr);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_346(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
