#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/htslib/htslib/sam.h" // Correct path for bam1_t and bam_destroy1

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    bam1_t *bam_record;

    // Allocate memory for bam1_t structure
    bam_record = (bam1_t *)malloc(sizeof(bam1_t));
    if (bam_record == NULL) {
        return 0; // Memory allocation failed
    }

    // Initialize bam1_t structure with some data
    bam_record->data = (uint8_t *)malloc(size);
    if (bam_record->data == NULL) {
        free(bam_record);
        return 0; // Memory allocation failed
    }
    memcpy(bam_record->data, data, size);
    bam_record->l_data = size;

    // Call the function-under-test
    bam_destroy1(bam_record);

    // No need to free bam_record or bam_record->data as bam_destroy1 should handle it

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

    LLVMFuzzerTestOneInput_8(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
