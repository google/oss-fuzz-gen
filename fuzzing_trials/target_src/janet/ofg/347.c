#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy

// Function-under-test
void janet_free(void *ptr);

// Fuzzing harness
int LLVMFuzzerTestOneInput_347(const uint8_t *data, size_t size) {
    // Allocate memory and ensure it's not NULL
    void *ptr = malloc(size > 0 ? size : 1); // Ensure at least 1 byte is allocated

    if (ptr != NULL) {
        // Copy the fuzzing data into the allocated memory
        memcpy(ptr, data, size);

        // Call the function-under-test
        janet_free(ptr);
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

    LLVMFuzzerTestOneInput_347(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
