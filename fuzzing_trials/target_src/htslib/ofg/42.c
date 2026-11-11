#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>  // Include the htslib library for bam1_t

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < sizeof(float) + 2) {
        return 0;
    }

    // Initialize bam1_t structure
    bam1_t *bam_record = bam_init1();
    if (bam_record == NULL) {
        return 0;
    }

    // Extract a float value from the data
    float float_value;
    memcpy(&float_value, data, sizeof(float));

    // Extract a string from the data for the tag
    char tag[3];
    memcpy(tag, data + sizeof(float), 2);
    tag[2] = '\0';  // Null-terminate the string

    // Call the function-under-test
    int result = bam_aux_update_float(bam_record, tag, float_value);

    // Clean up
    bam_destroy1(bam_record);

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

    LLVMFuzzerTestOneInput_42(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
