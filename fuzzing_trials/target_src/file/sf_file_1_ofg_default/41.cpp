#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>
#include <stdio.h>

extern "C" {
    // Function signature from the project
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // If magic_open fails, return early
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, return early
    }

    // Ensure the size is large enough to safely cast to an int
    if (size < sizeof(int)) {
        magic_close(magic);
        return 0;
    }

    // Use the first few bytes of data as an int descriptor
    int descriptor = *(const int *)data;

    // Call the function under test
    const char *result = magic_descriptor(magic, descriptor);

    // Use the result in some way to avoid compiler optimizing it away
    if (result != NULL && strlen(result) > 0) {
        // Print the result to ensure the function is being used and to provide more coverage
        printf("Magic descriptor result: %s\n", result);
    } else {
        // If result is NULL or empty, print a different message
        printf("Magic descriptor returned NULL or empty result.\n");
    }

    // Clean up
    magic_close(magic);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
