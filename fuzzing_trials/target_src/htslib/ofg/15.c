#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    bam1_t *original = bam_init1();
    bam1_t *duplicate = NULL;

    if (size < sizeof(bam1_core_t)) {
        bam_destroy1(original);
        return 0;
    }

    // Initialize bam1_t structure with the provided data
    memcpy(&original->core, data, sizeof(bam1_core_t));
    
    // Ensure data is large enough for the data and l_data fields
    if (size > sizeof(bam1_core_t)) {
        original->l_data = size - sizeof(bam1_core_t);
        original->data = (uint8_t *)malloc(original->l_data);
        if (original->data == NULL) {
            bam_destroy1(original);
            return 0;
        }
        memcpy(original->data, data + sizeof(bam1_core_t), original->l_data);
    } else {
        original->l_data = 0;
        original->data = NULL;
    }

    // Call the function-under-test
    duplicate = bam_dup1(original);

    // Clean up
    bam_destroy1(original);
    bam_destroy1(duplicate);

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

    LLVMFuzzerTestOneInput_15(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
