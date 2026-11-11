#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_335(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to create a context
    if (size < sizeof(void*)) {
        return 0;
    }

    // Create a cmsContext
    // Use a valid function to create a context, instead of casting data directly
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Optionally, you could use the data to perform some operations with the context
    // For example, you could use the data to create a profile or perform other operations

    // Call the function-under-test
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_335(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
