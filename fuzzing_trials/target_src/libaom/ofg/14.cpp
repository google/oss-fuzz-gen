#include <cstdint>
#include <cstddef>

extern "C" {
    #include "aom/aom_codec.h"  // Assuming the header file where OBU_TYPE is defined
    const char * aom_obu_type_to_string(OBU_TYPE type);
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Cast the first byte of data to OBU_TYPE
    OBU_TYPE obu_type = static_cast<OBU_TYPE>(data[0]);

    // Call the function-under-test
    const char *result = aom_obu_type_to_string(obu_type);

    // Use the result in some way to avoid optimization out
    if (result) {
        // For fuzzing purposes, we don't need to do anything with the result.
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
