#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    char *filename;
    struct bpf_link *link;

    // Ensure size is non-zero and limit it to a reasonable length for a filename
    if (size == 0 || size > 255) {
        return 0;
    }

    // Allocate memory for the filename and ensure it's null-terminated
    filename = (char *)malloc(size + 1);
    if (filename == NULL) {
        return 0;
    }
    memcpy(filename, data, size);
    filename[size] = '\0';

    // Call the function-under-test
    link = bpf_link__open(filename);

    // Clean up
    free(filename);

    // If a valid bpf_link was returned, close it
    if (link != NULL) {
        bpf_link__destroy(link);
    }

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

    LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
