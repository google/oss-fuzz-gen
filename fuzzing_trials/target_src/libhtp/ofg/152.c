#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

typedef struct {
    char *data;
    size_t len;
} bstr;

int bstr_index_of_mem_nocase(const bstr *b, const void *mem, size_t mem_len);

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Create a bstr object
    bstr b;
    b.data = (char *)malloc(size);
    if (b.data == NULL) return 0;
    memcpy(b.data, data, size);
    b.len = size;

    // Create a memory buffer to search for
    size_t mem_len = size / 2; // Use half of the data size for the search buffer
    const void *mem = data + mem_len;

    // Call the function-under-test
    int index = bstr_index_of_mem_nocase(&b, mem, mem_len);

    // Clean up
    free(b.data);

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

    LLVMFuzzerTestOneInput_152(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
