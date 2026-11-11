#include <stdint.h>
#include <stddef.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two tmsize_t values
    if (size < 2 * sizeof(tmsize_t)) {
        return 0;
    }

    // Extract two tmsize_t values from the input data
    tmsize_t num_elements = *(const tmsize_t *)(data);
    tmsize_t element_size = *(const tmsize_t *)(data + sizeof(tmsize_t));

    // Call the function-under-test
    void *result = _TIFFcalloc(num_elements, element_size);

    // If memory was allocated, free it
    if (result != NULL) {
        _TIFFfree(result);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
