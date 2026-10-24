#include <stdint.h>
#include <stddef.h>
#include "/src/gpac/src/isomedia/box_funcs.c" // Include the actual file where gf_isom_get_supported_box_type is implemented

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Ensure that the size is at least 4 bytes to safely extract a u32 value
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Extract a u32 value from the input data
    uint32_t idx = *(const uint32_t *)data;

    // Call the function-under-test
    gf_isom_get_supported_box_type(idx);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
