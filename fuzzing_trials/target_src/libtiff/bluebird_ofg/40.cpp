#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include <cstddef>
#include "tiffio.h"

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Ensure the size is a multiple of 3 for the function to operate correctly
    if (size < 3) {
        return 0;
    }

    // Allocate memory for the data copy to be swabbed
    uint8_t *triples = new uint8_t[size];
    
    // Copy the input data to the triples array
    for (size_t i = 0; i < size; ++i) {
        triples[i] = data[i];
    }

    // Call the function-under-test
    TIFFSwabArrayOfTriples(triples, static_cast<tmsize_t>(size / 3));

    // Clean up allocated memory
    delete[] triples;

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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
