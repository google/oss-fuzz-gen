#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assume the function is declared in an external library
void janet_clear_memory(void *ptr, size_t size);

int LLVMFuzzerTestOneInput_237(const uint8_t *data, size_t size) {
    // Allocate memory and copy the input data into it
    void *buffer = malloc(size);
    if (buffer == NULL) {
        return 0; // If allocation fails, return immediately
    }
    
    memcpy(buffer, data, size);

    // Call the function-under-test with the allocated buffer
    janet_clear_memory(buffer, size);
    
    // Free the allocated memory
    free(buffer);

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

    LLVMFuzzerTestOneInput_237(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
