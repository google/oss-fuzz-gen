#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "htslib/sam.h"  // Assuming sam_hdr_t is defined in this header

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for creating a valid string
    if (size < 2) {
        return 0;
    }

    // Initialize sam_hdr_t structure
    sam_hdr_t *hdr = sam_hdr_init();
    if (!hdr) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *pg_line = (char *)malloc(size + 1);
    if (!pg_line) {
        sam_hdr_destroy(hdr);
        return 0;
    }
    memcpy(pg_line, data, size);
    pg_line[size] = '\0';

    // Call the function to fuzz
    sam_hdr_add_pg(hdr, pg_line, NULL);

    // Clean up
    free(pg_line);
    sam_hdr_destroy(hdr);

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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
