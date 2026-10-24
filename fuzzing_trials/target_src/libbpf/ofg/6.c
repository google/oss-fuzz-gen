#include <stddef.h>
#include <stdint.h>
#include "/src/libbpf/src/libbpf.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    struct bpf_object *obj;
    char *path;
    int fd;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";

    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use as a pin path
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Allocate and initialize a dummy bpf_object
    obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        unlink(tmpl);
        return 0;
    }

    // Copy the temporary file path to a new buffer
    path = strdup(tmpl);
    if (!path) {
        bpf_object__close(obj);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    bpf_object__pin(obj, path);

    // Clean up
    bpf_object__close(obj);
    free(path);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
