#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    bam1_t *b = bam_init1();
    if (!b) return 0;

    // Ensure there is enough data to extract meaningful values
    if (size < 5) {
        bam_destroy1(b);
        return 0;
    }

    // Extract parameters from the input data
    const char *tag = (const char *)data;
    uint8_t type = data[2];
    uint32_t length = *((uint32_t *)(data + 3));

    // Ensure the length doesn't exceed the remaining data size
    if (length > size - 7) {
        bam_destroy1(b);
        return 0;
    }

    void *value = (void *)(data + 7);

    // Call the function under test
    bam_aux_update_array(b, tag, type, length, value);

    // Clean up
    bam_destroy1(b);

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

    LLVMFuzzerTestOneInput_147(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
