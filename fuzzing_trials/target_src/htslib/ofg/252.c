#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_252(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr;
    char *line;
    void *dummy = (void *)1; // A non-NULL void pointer

    // Initialize sam_hdr_t
    hdr = sam_hdr_init();
    if (hdr == NULL) {
        return 0;
    }

    // Ensure data is null-terminated for string operations
    line = (char *)malloc(size + 1);
    if (line == NULL) {
        sam_hdr_destroy(hdr);
        return 0;
    }
    memcpy(line, data, size);
    line[size] = '\0';

    // Call the function-under-test
    sam_hdr_add_line(hdr, line, dummy);

    // Clean up
    free(line);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_252(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
