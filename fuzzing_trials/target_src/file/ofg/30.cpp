#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" {
    // Include the function-under-test's header if available
    // extern const char * magic_getpath(const char *, int);
    const char * magic_getpath(const char *path, int flags);
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create a valid string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for a null-terminated string
    char *path = new char[size + 1];
    memcpy(path, data, size);
    path[size] = '\0'; // Null-terminate the string

    // Try different flag values
    int flags[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    size_t num_flags = sizeof(flags) / sizeof(flags[0]);

    for (size_t i = 0; i < num_flags; ++i) {
        // Call the function-under-test
        const char *result = magic_getpath(path, flags[i]);
        
        // Check if the result is not null and log it for debugging
        if (result != NULL) {
            printf("Result for flag %d: %s\n", flags[i], result);
        }
    }

    // Clean up
    delete[] path;
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
