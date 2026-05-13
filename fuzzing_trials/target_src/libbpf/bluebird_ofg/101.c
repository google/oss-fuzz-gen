#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libbpf.h"

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    struct bpf_map *map = NULL;
    char *path = NULL;
    int fd;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";

    // Ensure size is sufficient to create a file path
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use as the path
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Allocate and initialize the path
    path = strdup(tmpl);
    if (path == NULL) {
        return 0;
    }

    // Call the function-under-test
    bpf_map__unpin(map, path);

    // Clean up
    free(path);

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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
