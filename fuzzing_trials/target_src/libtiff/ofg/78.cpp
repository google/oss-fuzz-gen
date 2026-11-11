#include <cstdint>
#include <cstdlib>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    // Initialize the TIFFOpenOptions structure
    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (options == NULL) {
        return 0; // Exit if allocation fails
    }

    // Ensure the tmsize_t value is derived from the input data
    tmsize_t maxMemAlloc = 0;
    if (size >= sizeof(tmsize_t)) {
        maxMemAlloc = *reinterpret_cast<const tmsize_t*>(data);
    }

    // Fuzz the function-under-test
    TIFFOpenOptionsSetMaxCumulatedMemAlloc(options, maxMemAlloc);

    // Clean up
    TIFFOpenOptionsFree(options);

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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
