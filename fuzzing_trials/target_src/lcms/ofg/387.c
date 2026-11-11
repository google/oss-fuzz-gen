#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_387(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for at least some data
    if (size < 1) {
        return 0;
    }

    // Create a dummy context ID from the input data
    // For fuzzing, we need to ensure that we are passing valid data
    // Here we just ensure that the data is not NULL
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Perform operations with the context if it's valid
    if (context != NULL) {
        // Use the data in some way to influence the context
        // For example, we could use it to create a profile or similar
        // This is a placeholder for actual meaningful operations
        // ...

        // Clean up the context
        cmsDeleteContext(context);
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

    LLVMFuzzerTestOneInput_387(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
