#include <stddef.h>
#include <stdint.h>
#include "/src/libbpf/src/libbpf.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    struct bpf_object *obj = NULL;
    char path[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    // Ensure the size is sufficient to create a temporary file
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to be used as the path
    fd = mkstemp(path);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(path);
        return 0;
    }
    close(fd);

    // Call the function-under-test
    bpf_object__pin_programs(obj, path);

    // Clean up the temporary file
    unlink(path);

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
