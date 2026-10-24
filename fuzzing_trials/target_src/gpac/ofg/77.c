#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>
// Include the actual file where gf_isom_get_num_supported_boxes is implemented
// #include "/src/gpac/src/isomedia/box_funcs.c"

// Function prototype for the function-under-test
extern u32 gf_isom_get_num_supported_boxes();

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    // Ensure the input data is not null and has a meaningful size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Call the function-under-test
    u32 num_supported_boxes = gf_isom_get_num_supported_boxes();

    // Use the returned value to avoid compiler warnings about unused variables
    (void)num_supported_boxes;

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

    LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
