#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h> // Include the Little CMS library header

// Remove 'extern "C"' as it is not needed for C code
int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    cmsContext context;
    void *userData;

    // Initialize the context with some non-NULL value
    context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0; // If context creation fails, return early
    }

    // Call the function-under-test
    userData = cmsGetContextUserData(context);

    // Clean up the context
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

    LLVMFuzzerTestOneInput_32(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
