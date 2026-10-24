#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "htslib/sam.h"

int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    bam1_t *bam_record = bam_init1();
    char tag[3] = "XX"; // Initialize with a default tag
    int64_t value = 0;

    if (size < 2) {
        // Not enough data to set a tag and value, so clean up and return
        bam_destroy1(bam_record);
        return 0;
    }

    // Use the first two bytes of data as a tag
    tag[0] = (char)data[0];
    tag[1] = (char)data[1];

    // Use the remaining bytes as an int64_t value
    if (size >= 10) {
        memcpy(&value, data + 2, sizeof(int64_t));
    }

    // Call the function-under-test
    int result = bam_aux_update_int(bam_record, tag, value);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_119(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
