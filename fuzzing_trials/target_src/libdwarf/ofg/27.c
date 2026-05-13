#include <stddef.h>
#include <stdint.h>
#include <dwarf.h>

extern int dwarf_get_RLE_name(unsigned int, const char **);

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    unsigned int rle_value;
    const char *rle_name = "";

    // Ensure there's enough data to read an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Copy the data into the rle_value
    rle_value = *(unsigned int *)data;

    // Call the function-under-test
    dwarf_get_RLE_name(rle_value, &rle_name);

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

    LLVMFuzzerTestOneInput_27(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
