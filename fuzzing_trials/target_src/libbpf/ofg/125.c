#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/libbpf/src/libbpf.h"
#include <string.h>
#include <unistd.h>

// Fuzzing entry point
int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    struct bpf_object *obj = bpf_object__open("/path/to/bpf/object");
    char path[] = "/tmp/fuzzfileXXXXXX";

    // Ensure the object is opened successfully
    if (!obj) {
        return 0;
    }

    // Create a temporary file path
    int fd = mkstemp(path);
    if (fd == -1) {
        bpf_object__close(obj);
        return 0;
    }
    close(fd);

    // Call the function-under-test
    int result = bpf_object__pin_maps(obj, path);

    // Clean up
    unlink(path);
    bpf_object__close(obj);

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

    LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
