#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h> // Include the string.h header for strlen

extern "C" {
    // Declare the function-under-test
    const char *magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Extract an integer from the input data
    int descriptor = *(reinterpret_cast<const int*>(data));

    // Call the function-under-test
    const char *result = magic_descriptor(ms, descriptor);

    // Use the result in some way to prevent compiler optimizations
    if (result != NULL) {
        // Do something with the result, e.g., print or log it
        // For the purpose of fuzzing, we can just use it in a dummy operation
        volatile size_t dummy = strlen(result);
        (void)dummy;
    }

    // Clean up
    magic_close(ms);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
