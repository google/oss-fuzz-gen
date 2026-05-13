#include <stdint.h>
#include <stddef.h>

// Assuming the function is declared in a header file included in the project
// int32_t janet_abstract_decref_108(void *);

// Mock function definition for demonstration purposes
int32_t janet_abstract_decref_108(void *ptr) {
    // Implementation of the function
    // For demonstration, just return a dummy value
    return 0;
}

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a non-NULL pointer
    if (size < sizeof(void *)) {
        return 0;
    }

    // Use the data as a pointer
    void *ptr = (void *)data;

    // Call the function-under-test
    int32_t result = janet_abstract_decref_108(ptr);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_108(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
