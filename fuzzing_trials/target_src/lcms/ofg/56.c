#include <stdint.h>
#include <stddef.h>  // Include this for size_t
#include <lcms2.h>

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int input_value = *(int*)data;

    // Call the function-under-test
    cmsColorSpaceSignature result = _cmsICCcolorSpace(input_value);

    // Use the result in some way to avoid compiler optimizations
    // (e.g., printing or storing it)
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

    LLVMFuzzerTestOneInput_56(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
