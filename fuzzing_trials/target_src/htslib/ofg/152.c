#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    // Open a BAM file for writing in memory
    htsFile *file = hts_open("temp.bam", "wb");
    if (file == NULL) {
        return 0;
    }

    // Ensure the data is null-terminated to safely use it as a string
    char *filter_expr = (char *)malloc(size + 1);
    if (filter_expr == NULL) {
        hts_close(file);
        return 0;
    }
    memcpy(filter_expr, data, size);
    filter_expr[size] = '\0';

    // Call the function-under-test with a non-null filter expression
    if (strlen(filter_expr) > 0) {
        hts_set_filter_expression(file, filter_expr);
    }

    // Clean up
    free(filter_expr);
    hts_close(file);

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

    LLVMFuzzerTestOneInput_152(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
